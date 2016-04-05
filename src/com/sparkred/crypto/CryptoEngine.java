/*
 * Please read the README.md and LICENSE.md files contained in this repository or module.
 *
 * Please contact sales@sparkred.com or support@sparkred.com if you have any questions.
 *
 * This code is copyright Spark::red https://www.sparkred.com 2007-2016, all right reserved.
 */
package com.sparkred.crypto;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.text.DateFormat;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

import atg.nucleus.GenericService;
import atg.nucleus.ServiceException;
import atg.repository.MutableRepository;
import atg.repository.MutableRepositoryItem;
import atg.repository.RepositoryException;
import atg.repository.RepositoryItem;
import atg.service.email.EmailEvent;
import atg.service.email.EmailException;
import atg.service.email.SMTPEmailSender;
import atg.service.scheduler.Schedulable;
import atg.service.scheduler.Schedule;
import atg.service.scheduler.ScheduledJob;
import atg.service.scheduler.Scheduler;

/**
 * The Class CryptoEngine handles encrypting and de-crypting data using AES 256 bit encryption.
 */
public class CryptoEngine extends GenericService implements Schedulable, Serializable {

	/**
	 * Generated serial version UID.
	 */
	private static final long serialVersionUID = 5491613272379694854L;

	/** The key passphrase. */
	private String mKeyPassphrase;

	/** The crypto engine identifier for the crypto engine config to be used by this component. */
	private String mCryptoEngineIdentifier;

	/** The crypto engine description. */
	private String mCryptoEngineDescription;

	/** The crypto repository. */
	private MutableRepository mCryptoRepository;

	/** The internal encryptor to use. */
	private StandardPBEStringEncryptor mEncryptor;

	/** The Scheduler. */
	private Scheduler mScheduler;

	/** The Schedule. */
	private Schedule mSchedule;

	/** The Job id for the scheduler. */
	private int mJobId;

	/** The Key expiration days. */
	private int mKeyExpirationDays;

	/** The Key expiration notification days. */
	private int mKeyExpirationNotificationDays;

	/** The Key expiration notification email. */
	private String mKeyExpirationNotificaitonEmail;

	/** The SMTP email sender component. */
	private SMTPEmailSender mSMTPEmailSender;

	/**
	 * The Check key expiration flag to determine if a warning email should be sent if a key is nearing its expiration
	 * date.
	 */
	private boolean mCheckKeyExpiration;

	/**
	 * Do start service.
	 *
	 * @throws ServiceException
	 *             the service exception
	 * @see atg.nucleus.GenericService#doStartService()
	 */
	@Override
	public void doStartService() throws ServiceException {
		// Validate required properties
		if (getCryptoRepository() == null) {
			if (isLoggingError()) {
				logError("CryptoEngine.doStartService: " + "CryptoRepository was null.");
			}
			throw new ServiceException("CryptoRepository was null.");
		}
		if (getCryptoEngineIdentifier() == null) {
			if (isLoggingError()) {
				logError("CryptoEngine.doStartService: " + "CryptoEngineIdentifier was null.");
			}
			throw new ServiceException("CryptoEngineIdentifier was null.");
		}
		if (getKeyPassphrase() == null) {
			if (isLoggingError()) {
				logError("CryptoEngine.doStartService: " + "KeyPassphrase was null.");
			}
			throw new ServiceException("KeyPassphrase was null.");
		}

		// Add the BouncyCastle JCE Security provider
		Security.addProvider(new BouncyCastleProvider());

		try {
			// Load this crypo engine's encrypted data passphrase
			RepositoryItem cryptoEngineItem = getCryptoRepository().getItem(getCryptoEngineIdentifier(),
					CryptoConstants.CRYPTO_ENGINE_ITEM_DESC);
			if (cryptoEngineItem == null) {
				if (isLoggingWarning()) {
					logWarning("CryptoEngine.doStartService: "
							+ "This Crypto Engine has not yet been initialized.  Initializing it now.");
				}
				initializeNewEngine();
				cryptoEngineItem = getCryptoRepository().getItem(getCryptoEngineIdentifier(),
						CryptoConstants.CRYPTO_ENGINE_ITEM_DESC);
			}
			String encryptedDataPassphrase = (String) cryptoEngineItem
					.getPropertyValue(CryptoConstants.ENC_DATA_KEY_PROP_NAME);

			// Decrypt the data passphrase using the key passphrase
			final StandardPBEStringEncryptor dataPassDecryptor = new StandardPBEStringEncryptor();
			dataPassDecryptor.setProviderName(CryptoConstants.BOUNCY_CASTLE_PROVIDER_NAME);
			dataPassDecryptor.setAlgorithm(CryptoConstants.STRONG_ALGO);
			dataPassDecryptor.setPassword(getKeyPassphrase());

			String dataPassphrase = dataPassDecryptor.decrypt(encryptedDataPassphrase);
			if (isLoggingInfo()) {
				logInfo("CryptoEngine.doStartService: " + "dataPassphrase is: " + dataPassphrase);
			}
			// Setup the encryptor
			this.mEncryptor = new StandardPBEStringEncryptor();
			this.mEncryptor.setProviderName(CryptoConstants.BOUNCY_CASTLE_PROVIDER_NAME);
			this.mEncryptor.setAlgorithm(CryptoConstants.STRONG_ALGO);
			this.mEncryptor.setPassword(dataPassphrase);
		} catch (Exception e) {
			if (isLoggingError()) {
				logError("CryptoEngine.doStartService: " + "Exception caught setting up the encryptor.", e);
			}
		}

		// Setup scheduled job to check the key expiration status
		ScheduledJob job = new ScheduledJob("SR:Crypto:" + getCryptoEngineIdentifier(),
				"Checks the key expiration status for the Spark::red encryptor: " + getCryptoEngineIdentifier(),
				getAbsoluteName(), getSchedule(), this, ScheduledJob.SCHEDULER_THREAD);
		setJobId(getScheduler().addScheduledJob(job));
	}

	/**
	 * Initialize engine for first time use. This method created a new random data encryption passphrase which is shown
	 * to no one.
	 */
	private void initializeNewEngine() {
		// Generate a new data passphrase
		String newDataPassphrase = generateNewDataPassphrase();
		// Encrypt the data passphrase with the key passphrase
		final StandardPBEStringEncryptor dataPassEncryptor = new StandardPBEStringEncryptor();
		dataPassEncryptor.setProviderName(CryptoConstants.BOUNCY_CASTLE_PROVIDER_NAME);
		dataPassEncryptor.setAlgorithm(CryptoConstants.STRONG_ALGO);
		dataPassEncryptor.setPassword(getKeyPassphrase());
		String encryptedNewDataPassphrase = dataPassEncryptor.encrypt(newDataPassphrase);

		// Persist the new engine config
		try {
			MutableRepositoryItem newCryptoEngineItem = getCryptoRepository().createItem(getCryptoEngineIdentifier(),
					CryptoConstants.CRYPTO_ENGINE_ITEM_DESC);
			newCryptoEngineItem.setPropertyValue(CryptoConstants.DESCRIPTION_PROP_NAME, getCryptoEngineDescription());
			newCryptoEngineItem.setPropertyValue(CryptoConstants.ENC_DATA_KEY_PROP_NAME, encryptedNewDataPassphrase);
			newCryptoEngineItem.setPropertyValue(CryptoConstants.KEY_DATE_PROP_NAME, new Date());
			getCryptoRepository().addItem(newCryptoEngineItem);
		} catch (RepositoryException e) {
			if (isLoggingError()) {
				logError("CryptoEngine.initializeEngine: " + "unable to create new crypto engine config item.", e);
			}
		}
	}

	/**
	 * Generate new data password.
	 *
	 * @return the string
	 */
	private String generateNewDataPassphrase() {
		String newDataPassphrase = new BigInteger(130, new SecureRandom()).toString(32);
		if (isLoggingDebug()) {
			logDebug("RekeyEngine.generateNewDataPassphrase: " + "newDataPassphrase is: " + newDataPassphrase);
		}
		return newDataPassphrase;
	}

	/**
	 * Checks the key expiration situation daily.
	 *
	 * @param pArg0
	 *            the arg0
	 * @param pArg1
	 *            the arg1
	 * @see atg.service.scheduler.Schedulable#performScheduledTask(atg.service.scheduler.Scheduler,
	 *      atg.service.scheduler.ScheduledJob)
	 */
	public void performScheduledTask(Scheduler pArg0, ScheduledJob pArg1) {
		if (isCheckKeyExpiration()) {
			checkKeyExpiration();
		}
	}

	/**
	 * This method checks the last ReKey date against the key expiration period, and the key expiration notification
	 * period, and sends out e-mails if the key is close to expiring and will need to be ReKeyed.
	 */
	private void checkKeyExpiration() {
		try {
			// Check current key gen date
			RepositoryItem cryptoEngineItem = getCryptoRepository().getItem(getCryptoEngineIdentifier(),
					CryptoConstants.CRYPTO_ENGINE_ITEM_DESC);
			if (cryptoEngineItem != null) {
				Date keyDate = (Date) cryptoEngineItem.getPropertyValue(CryptoConstants.KEY_DATE_PROP_NAME);
				if (keyDate != null) {
					Calendar notificationDate = Calendar.getInstance();
					// Get a string representation of the last key impl date
					String keyDateString = DateFormat.getDateInstance(DateFormat.MEDIUM).format(keyDate);
					// Set it to the last ReKey date
					notificationDate.setTime(keyDate);
					// Add the expiration days
					notificationDate.add(Calendar.DAY_OF_YEAR, getKeyExpirationDays());
					String expirationDateString = DateFormat.getDateInstance(DateFormat.MEDIUM)
							.format(notificationDate.getTime());
					// Subtract the notification threshold
					notificationDate.add(Calendar.DAY_OF_YEAR, -getKeyExpirationNotificationDays());
					if (notificationDate.before(Calendar.getInstance())) {
						// Send e-mail
						EmailEvent notificationEmailEvent = new EmailEvent();
						notificationEmailEvent.setFrom(getSMTPEmailSender().getDefaultFrom());
						notificationEmailEvent.setRecipient(getKeyExpirationNotificaitonEmail());
						notificationEmailEvent.setSubject(
								"ATG Crypto Key needs to be ReKeyed soon! - " + getCryptoEngineIdentifier());
						notificationEmailEvent
								.setBody("The encryption key for the Spark::red ATG CryptoEngine with the identifier: "
										+ getCryptoEngineIdentifier()
										+ " will expire soon.  The current encryption key was put into service on: "
										+ keyDateString + " and should be ReKeyed before: " + expirationDateString
										+ ".  You will recieve this e-mail every day until the engine has been ReKeyed.");
						getSMTPEmailSender().sendEmailEvent(notificationEmailEvent);
					}
				}
			}
		} catch (RepositoryException e) {
			if (isLoggingError()) {
				logError("CryptoEngine.checkKeyExpiration: "
						+ "RepositoryException while trying to load the crypto engine config data for identfier: "
						+ getCryptoEngineIdentifier(), e);
			}
		} catch (EmailException e) {
			if (isLoggingError()) {
				logError("CryptoEngine.checkKeyExpiration: "
						+ "EmailException while trying to send an upcoming key expiration notification e-mail to: "
						+ getKeyExpirationNotificaitonEmail(), e);
			}
		}
	}

	/**
	 * Test.
	 */
	public void test() {
		String text = "1234567890123456";
		if (isLoggingError()) {
			logError("CryptoEngine.test: " + "text: " + text);
		}
		String encryptedText = encrypt(text);

		if (isLoggingError()) {
			logError("CryptoEngine.test: " + "encryptedText: " + encryptedText);
		}

		String decryptedText = decrypt(encryptedText);
		if (isLoggingError()) {
			logError("CryptoEngine.test: " + "decryptedText: " + decryptedText);
		}

		String cc1 = "UE4rqdnKfZOKySN9YNRJ+lhuGdJIJgX1ArcA7rPz08SnlR+sEJKwKw4bYutvpd8o";
		String cc1Dec = decrypt(cc1);
		if (isLoggingError()) {
			logError("CryptoEngine.test: " + "cc1Dec: " + cc1Dec);
		}
	}

	/**
	 * Do stop service.
	 *
	 * @throws ServiceException
	 *             the service exception
	 * @see atg.nucleus.GenericService#doStopService()
	 */
	@Override
	public void doStopService() throws ServiceException {
		getScheduler().removeScheduledJob(getJobId());
	}

	/**
	 * Decrypt.
	 *
	 * @param pEncryptedText
	 *            the encrypted text
	 * @return the string
	 */
	public String decrypt(String pEncryptedText) {
		return this.mEncryptor.decrypt(pEncryptedText);
	}

	/**
	 * Encrypt.
	 *
	 * @param pPlainText
	 *            the plain text
	 * @return the string
	 */
	public String encrypt(String pPlainText) {
		return this.mEncryptor.encrypt(pPlainText);
	}

	/**
	 * Gets the key passphrase.
	 *
	 * @return the key passphrase
	 */
	public String getKeyPassphrase() {
		return mKeyPassphrase;
	}

	/**
	 * Sets the key passphrase.
	 *
	 * @param pKeyPassphrase
	 *            the new key passphrase
	 */
	public void setKeyPassphrase(String pKeyPassphrase) {
		mKeyPassphrase = pKeyPassphrase;
	}

	/**
	 * Gets the crypto engine identifier.
	 *
	 * @return the crypto engine identifier
	 */
	public String getCryptoEngineIdentifier() {
		return mCryptoEngineIdentifier;
	}

	/**
	 * Sets the crypto engine identifier.
	 *
	 * @param pCryptoEngineIdentifier
	 *            the new crypto engine identifier
	 */
	public void setCryptoEngineIdentifier(String pCryptoEngineIdentifier) {
		mCryptoEngineIdentifier = pCryptoEngineIdentifier;
	}

	/**
	 * Gets the crypto repository.
	 *
	 * @return the crypto repository
	 */
	public MutableRepository getCryptoRepository() {
		return mCryptoRepository;
	}

	/**
	 * Sets the crypto repository.
	 *
	 * @param pCryptoRepository
	 *            the new crypto repository
	 */
	public void setCryptoRepository(MutableRepository pCryptoRepository) {
		mCryptoRepository = pCryptoRepository;
	}

	/**
	 * Gets the crypto engine description.
	 *
	 * @return the crypto engine description
	 */
	public String getCryptoEngineDescription() {
		return mCryptoEngineDescription;
	}

	/**
	 * Sets the crypto engine description.
	 *
	 * @param pCryptoEngineDescription
	 *            the new crypto engine description
	 */
	public void setCryptoEngineDescription(String pCryptoEngineDescription) {
		mCryptoEngineDescription = pCryptoEngineDescription;
	}

	/**
	 * Gets the scheduler.
	 *
	 * @return the scheduler
	 */
	public Scheduler getScheduler() {
		return mScheduler;
	}

	/**
	 * Sets the scheduler.
	 *
	 * @param pScheduler
	 *            the new scheduler
	 */
	public void setScheduler(Scheduler pScheduler) {
		mScheduler = pScheduler;
	}

	/**
	 * Gets the schedule.
	 *
	 * @return the schedule
	 */
	public Schedule getSchedule() {
		return mSchedule;
	}

	/**
	 * Sets the schedule.
	 *
	 * @param pSchedule
	 *            the new schedule
	 */
	public void setSchedule(Schedule pSchedule) {
		mSchedule = pSchedule;
	}

	/**
	 * Gets the job id.
	 *
	 * @return the job id
	 */
	public int getJobId() {
		return mJobId;
	}

	/**
	 * Sets the job id.
	 *
	 * @param pJobId
	 *            the new job id
	 */
	public void setJobId(int pJobId) {
		mJobId = pJobId;
	}

	/**
	 * Gets the key expiration days.
	 *
	 * @return the key expiration days
	 */
	public int getKeyExpirationDays() {
		return mKeyExpirationDays;
	}

	/**
	 * Sets the key expiration days.
	 *
	 * @param pKeyExpirationDays
	 *            the new key expiration days
	 */
	public void setKeyExpirationDays(int pKeyExpirationDays) {
		mKeyExpirationDays = pKeyExpirationDays;
	}

	/**
	 * Gets the key expiration notification days.
	 *
	 * @return the key expiration notification days
	 */
	public int getKeyExpirationNotificationDays() {
		return mKeyExpirationNotificationDays;
	}

	/**
	 * Sets the key expiration notification days.
	 *
	 * @param pKeyExpirationNotificationDays
	 *            the new key expiration notification days
	 */
	public void setKeyExpirationNotificationDays(int pKeyExpirationNotificationDays) {
		mKeyExpirationNotificationDays = pKeyExpirationNotificationDays;
	}

	/**
	 * Gets the key expiration notificaiton email.
	 *
	 * @return the key expiration notificaiton email
	 */
	public String getKeyExpirationNotificaitonEmail() {
		return mKeyExpirationNotificaitonEmail;
	}

	/**
	 * Sets the key expiration notificaiton email.
	 *
	 * @param pKeyExpirationNotificaitonEmail
	 *            the new key expiration notificaiton email
	 */
	public void setKeyExpirationNotificaitonEmail(String pKeyExpirationNotificaitonEmail) {
		mKeyExpirationNotificaitonEmail = pKeyExpirationNotificaitonEmail;
	}

	/**
	 * Gets the SMTP email sender.
	 *
	 * @return the SMTP email sender
	 */
	public SMTPEmailSender getSMTPEmailSender() {
		return mSMTPEmailSender;
	}

	/**
	 * Sets the SMTP email sender.
	 *
	 * @param pSMTPEmailSender
	 *            the new SMTP email sender
	 */
	public void setSMTPEmailSender(SMTPEmailSender pSMTPEmailSender) {
		mSMTPEmailSender = pSMTPEmailSender;
	}

	/**
	 * Checks if is check key expiration.
	 *
	 * @return true, if is check key expiration
	 */
	public boolean isCheckKeyExpiration() {
		return mCheckKeyExpiration;
	}

	/**
	 * Sets the check key expiration.
	 *
	 * @param pCheckKeyExpiration
	 *            the new check key expiration
	 */
	public void setCheckKeyExpiration(boolean pCheckKeyExpiration) {
		mCheckKeyExpiration = pCheckKeyExpiration;
	}

}
