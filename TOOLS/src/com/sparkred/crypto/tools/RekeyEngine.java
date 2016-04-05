/*
 * Please read the README.md and LICENSE.md files contained in this repository or module.
 *
 * Please contact sales@sparkred.com or support@sparkred.com if you have any questions.
 *
 * This code is copyright Spark::red https://www.sparkred.com 2007-2016, all right reserved.
 */
package com.sparkred.crypto.tools;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Date;
import java.util.List;

import javax.sql.DataSource;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

import atg.core.util.StringUtils;
import atg.nucleus.GenericService;
import atg.nucleus.ServiceException;
import atg.repository.MutableRepository;
import atg.repository.MutableRepositoryItem;
import atg.repository.RepositoryException;

import com.sparkred.crypto.CryptoConstants;
import com.sparkred.crypto.CryptoEngine;

/**
 * The Class RekeyEngine is used to do initial import encryptions from either plaintext columns or from data encrypted
 * with another type of encryption. It's also used to rekey and reencrypt data every 12 months.
 */
public class RekeyEngine extends GenericService {

	/** The crypto repository. */
	private MutableRepository mCryptoRepository;

	/** The data source for the data to be rekeyed. */
	private DataSource mDataDataSource;

	/** The decryptor component. */
	private Object mDecryptorComponent;

	/** The decryptor method. */
	private String mDecryptorMethod;

	/** The new key passphrase. */
	private String mNewKeyPassphrase;

	/** The table columns. */
	private List<String> mTableColumns;

	/** The engine to update. */
	private CryptoEngine mEngineToUpdate;

	/** The decrypt method. */
	private Method mDecryptMethod;

	/** The encryptor. */
	private StandardPBEStringEncryptor mEncryptor;

	/** The new data passphrase. */
	private String mNewDataPassphrase;

	/**
	 * Initializes the decryptMethod, generates a new data passphrase, and sets up the local encryptor component.
	 *
	 * @throws SecurityException
	 *             the security exception
	 * @throws NoSuchMethodException
	 *             the no such method exception
	 */
	private void initialize() throws SecurityException, NoSuchMethodException {
		if (isLoggingDebug()) {
			logDebug("RekeyEngine.initialize:" + "starting....");
		}
		// Add the BouncyCastle JCE Security provider
		Security.addProvider(new BouncyCastleProvider());

		// Generate new data passphrase
		this.mNewDataPassphrase = generateNewDataPassphrase();
		if (isLoggingDebug()) {
			logDebug("RekeyEngine.initialize:" + "new data passphrase was generated:" + this.mNewDataPassphrase);
		}
		// Setup the decryptor
		Class[] decryptMethodArgs = new Class[1];
		decryptMethodArgs[0] = String.class;
		Method decryptMethod = getDecryptorComponent().getClass().getMethod(getDecryptorMethod(), decryptMethodArgs);
		this.mDecryptMethod = decryptMethod;
		if (isLoggingDebug()) {
			logDebug("RekeyEngine.initialize:" + "decryptMethod is setup.");
		}

		// Setup the encryptor
		StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
		encryptor.setProviderName(CryptoConstants.BOUNCY_CASTLE_PROVIDER_NAME);
		encryptor.setAlgorithm(CryptoConstants.STRONG_ALGO);
		encryptor.setPassword(this.mNewDataPassphrase);
		this.mEncryptor = encryptor;
		if (isLoggingDebug()) {
			logDebug("RekeyEngine.initialize:" + "encryptor is setup.");
		}
	}

	/**
	 * Rekey. This method performs batch decrypt and encrypt operations on one or more columns in the database. It can
	 * be used to perform initial encryption of plain text data, re-encrypt data that was encrypted with another system,
	 * or re-encrypt data with a new key to meet PCI key rotation requirements.
	 */
	public void reKey() {
		// UserTransactionDemarcation td = new UserTransactionDemarcation();
		// try {
		// try {
		// td.begin();
		// Setup JDBC connection
		Connection dataConnection = null;
		ResultSet rs = null;
		Statement selectStmt = null;
		try {
			initialize();

			dataConnection = getDataDataSource().getConnection();
			dataConnection.setAutoCommit(false);
			if (isLoggingDebug()) {
				logDebug("RekeyEngine.reKey:" + "dataconnection is set.");
			}
			// For each column we need to update...
			for (String tableColumn : getTableColumns()) {
				if (!StringUtils.isBlank(tableColumn) && tableColumn.split("\\.") != null
						&& tableColumn.split("\\.").length == 2) {
					String[] columnData = tableColumn.split("\\.");
					String tableName = columnData[0];
					String columnName = columnData[1];

					// Load up values
					String selectQuery = "SELECT " + columnName + " FROM " + tableName;
					if (isLoggingDebug()) {
						logDebug("RekeyEngine.reKey:" + "selectQuery: " + selectQuery);
					}
					selectStmt = dataConnection.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE,
							ResultSet.CONCUR_UPDATABLE);
					rs = selectStmt.executeQuery(selectQuery);
					while (rs.next()) {
						if (isLoggingDebug()) {
							logDebug("RekeyEngine.reKey:" + "about to work on Row ID: " + rs.getRowId(1));
							logDebug("RekeyEngine.reKey:" + "about to work on Row Num: " + rs.getRow());
						}
						String encryptedString = rs.getString(1);
						if (isLoggingDebug()) {
							logDebug("RekeyEngine.reKey:" + "initial encrypted string: " + encryptedString);
						}
						// Decrypt using the referenced component and method
						String decryptedString = (String) this.mDecryptMethod.invoke(getDecryptorComponent(),
								encryptedString);

						if (isLoggingDebug()) {
							logDebug("RekeyEngine.reKey:" + "decrypted string: " + decryptedString);
						}
						// Encrypt using the new local encryptor using the new passphrase
						String reEncryptedString = this.mEncryptor.encrypt(decryptedString);

						if (isLoggingDebug()) {
							logDebug("RekeyEngine.reKey:" + "re-encrypted string: " + reEncryptedString);
						}
						// Update the record
						rs.updateString(columnName, reEncryptedString);
						rs.updateRow();
						if (isLoggingDebug()) {
							logDebug("RekeyEngine.reKey:" + "updated Row ID: " + rs.getRowId(1));
							logDebug("RekeyEngine.reKey:" + "updated Row Num: " + rs.getRow());
						}
					}
				}
			}

			// Encrypt the new passphrase
			final StandardPBEStringEncryptor dataPassEncryptor = new StandardPBEStringEncryptor();
			dataPassEncryptor.setProviderName(CryptoConstants.BOUNCY_CASTLE_PROVIDER_NAME);
			dataPassEncryptor.setAlgorithm(CryptoConstants.STRONG_ALGO);
			dataPassEncryptor.setPassword(getNewKeyPassphrase());
			String encryptedNewDataPassphrase = dataPassEncryptor.encrypt(this.mNewDataPassphrase);
			// Load crypto engine data
			MutableRepositoryItem cryptoEngineItem = getCryptoRepository().getItemForUpdate(
					getEngineToUpdate().getCryptoEngineIdentifier(), CryptoConstants.CRYPTO_ENGINE_ITEM_DESC);

			// Persist the new data passphrase
			cryptoEngineItem.setPropertyValue(CryptoConstants.ENC_DATA_KEY_PROP_NAME, encryptedNewDataPassphrase);
			cryptoEngineItem.setPropertyValue(CryptoConstants.KEY_DATE_PROP_NAME, new Date());
			getCryptoRepository().updateItem(cryptoEngineItem);
			if (isLoggingDebug()) {
				logDebug("RekeyEngine.reKey:" + "crypto config saved.");
			}

		} catch (SQLException sqle) {
			if (isLoggingError()) {
				logError("RekeyEngine.reKey:" + "SQLException:", sqle);
			}
		} catch (InvocationTargetException ite) {
			if (isLoggingError()) {
				logError("RekeyEngine.reKey:" + "InvocationTargetException:", ite);
			}
		} catch (IllegalAccessException iae) {
			if (isLoggingError()) {
				logError("RekeyEngine.reKey:" + "IllegalAccessException:", iae);
			}
		} catch (NoSuchMethodException nsme) {
			if (isLoggingError()) {
				logError("RekeyEngine.reKey:" + "NoSuchMethodException:", nsme);
			}
		} catch (RepositoryException re) {
			if (isLoggingError()) {
				logError("RekeyEngine.reKey:" + "RepositoryException:", re);
			}
		} finally {
			if (dataConnection != null) {
				try {
					if (rs != null) {
						rs.close();
					}
					dataConnection.commit();
					dataConnection.close();
				} catch (SQLException e) {
					if (isLoggingError()) {
						logError("RekeyEngine.reKey:" + "unable to close data connection.", e);
					}
				}
			}
		}

		// finally {
		// td.end();
		// }
		// } catch (TransactionDemarcationException tde) {
		// if (isLoggingError()) {
		// logError("RekeyEngine.reKey:" + "Transaction Exception.", tde);
		// }
		// } catch (RepositoryException e) {
		// if (isLoggingError()) {
		// logError("RekeyEngine.reKey:" + "Repository Exception.", e);
		// }
		// }

	}

	/**
	 * Generate new data password.
	 *
	 * @return the string
	 */
	private String generateNewDataPassphrase() {
		String newDataPassphrase = new BigInteger(130, new SecureRandom()).toString(32);
		if (isLoggingDebug()) {
			logDebug("RekeyEngine.generateNewDataPassphrase:" + "newDataPassphrase is: " + newDataPassphrase);
		}
		return newDataPassphrase;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see atg.nucleus.GenericService#doStartService()
	 */
	@Override
	public void doStartService() throws ServiceException {
		// TODO Validations
	}

	/**
	 * Gets the decryptor component.
	 *
	 * @return the decryptor component
	 */
	public Object getDecryptorComponent() {
		return mDecryptorComponent;
	}

	/**
	 * Sets the decryptor component.
	 *
	 * @param pDecryptorComponent
	 *            the new decryptor component
	 */
	public void setDecryptorComponent(Object pDecryptorComponent) {
		mDecryptorComponent = pDecryptorComponent;
	}

	/**
	 * Gets the decryptor method.
	 *
	 * @return the decryptor method
	 */
	public String getDecryptorMethod() {
		return mDecryptorMethod;
	}

	/**
	 * Sets the decryptor method.
	 *
	 * @param pDecryptorMethod
	 *            the new decryptor method
	 */
	public void setDecryptorMethod(String pDecryptorMethod) {
		mDecryptorMethod = pDecryptorMethod;
	}

	/**
	 * Gets the new key passphrase.
	 *
	 * @return the new key passphrase
	 */
	public String getNewKeyPassphrase() {
		return mNewKeyPassphrase;
	}

	/**
	 * Sets the new key passphrase.
	 *
	 * @param pNewKeyPassphrase
	 *            the new new key passphrase
	 */
	public void setNewKeyPassphrase(String pNewKeyPassphrase) {
		mNewKeyPassphrase = pNewKeyPassphrase;
	}

	/**
	 * Gets the data data source.
	 *
	 * @return the data data source
	 */
	public DataSource getDataDataSource() {
		return mDataDataSource;
	}

	/**
	 * Sets the data data source.
	 *
	 * @param pDataDataSource
	 *            the new data data source
	 */
	public void setDataDataSource(DataSource pDataDataSource) {
		mDataDataSource = pDataDataSource;
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
	 * Gets the table columns.
	 *
	 * @return the table columns
	 */
	public List<String> getTableColumns() {
		return mTableColumns;
	}

	/**
	 * Sets the table columns.
	 *
	 * @param pTableColumns
	 *            the new table columns
	 */
	public void setTableColumns(List<String> pTableColumns) {
		mTableColumns = pTableColumns;
	}

	/**
	 * Gets the engine to update.
	 *
	 * @return the engine to update
	 */
	public CryptoEngine getEngineToUpdate() {
		return mEngineToUpdate;
	}

	/**
	 * Sets the engine to update.
	 *
	 * @param pEngineToUpdate
	 *            the new engine to update
	 */
	public void setEngineToUpdate(CryptoEngine pEngineToUpdate) {
		mEngineToUpdate = pEngineToUpdate;
	}
}
