/*
 * Please read the README.md and LICENSE.md files contained in this repository or module.
 *
 * Please contact sales@sparkred.com or support@sparkred.com if you have any questions.
 *
 * This code is copyright Spark::red https://www.sparkred.com 2007-2016, all right reserved.
 */
package com.sparkred.crypto;

import java.io.Serializable;

import atg.adapter.gsa.GSAPropertyDescriptor;
import atg.nucleus.Nucleus;
import atg.repository.RepositoryImpl;
import atg.repository.RepositoryItemDescriptor;
import atg.repository.RepositoryItemImpl;

/**
 * The Class CryptoPropertyDescriptor.
 */
public class CryptoPropertyDescriptor extends GSAPropertyDescriptor implements Serializable {

	/** The Constant TRUE_STRING. */
	private static final String TRUE_STRING = "true";

	/**
	 * Generated UID.
	 */
	private static final long serialVersionUID = 7882011569806958779L;

	/**
	 * The type name property.
	 */
	private static final String TYPE_NAME = "encrypted";

	/**
	 * The encryptor component path property.
	 */
	private static final String CRYPTO_ENGINE = "cryptoEngine";

	/** The encrypt only attribute flag. */
	private static final String ENCRYPT_ONLY = "encryptOnly";

	/**
	 * The Encryptor Component to use. This is set to a string to avoid serialization issues that impact the ACC.
	 * https://www.sparkred.com/jira/browse/QSSPRT-128
	 */
	private String mCryptoEngineName;

	/** The encrypt only flag. */
	private boolean mEncryptOnly = false;

	/**
	 * Constructs a EncryptionPropertyDescriptor.
	 */
	public CryptoPropertyDescriptor() {
		super();
	}

	/**
	 * Returns property Queryable.
	 *
	 * @return as the property is always queryable
	 */
	public boolean isQueryable() {
		return true;
	}

	/**
	 * Sets the property of this type for the item descriptor provided.
	 *
	 * @param pItem
	 *            the RepositoryItem to set the value for
	 * @param pValue
	 *            the value to set to the item.
	 */
	public void setPropertyValue(final RepositoryItemImpl pItem, final Object pValue) {
		if (pValue == null) {
			return;
		}
		CryptoEngine cryptoEngine = (CryptoEngine) Nucleus.getGlobalNucleus().resolveName(this.mCryptoEngineName);
		if (cryptoEngine == null) {
			logError("Property Item Descriptor: " + getItemDescriptor().getItemDescriptorName() + "." + getName()
					+ " not property configured.");
			throw new NullPointerException("Crypto Engine not configured " + getItemDescriptor().getItemDescriptorName()
					+ "." + getPropertyItemDescriptor().getItemDescriptorName());
		}
		super.setPropertyValue(pItem, cryptoEngine.encrypt(pValue.toString()));
	}

	/**
	 * Returns the value of the underlying property.
	 *
	 * @param pItem
	 *            the RepositoryItem to retrieve the value from
	 * @param pValue
	 *            the value to retrieve
	 * @return The property value requested
	 */
	public Object getPropertyValue(final RepositoryItemImpl pItem, final Object pValue) {
		// If the object value is null or "the null object", then simply return
		// null.
		if ((pValue == null) || pValue == RepositoryItemImpl.NULL_OBJECT) {
			return null;
		}
		if (isEncryptOnly()) {
			return super.getPropertyValue(pItem, pValue);
		} else {
			CryptoEngine cryptoEngine = (CryptoEngine) Nucleus.getGlobalNucleus().resolveName(this.mCryptoEngineName);
			if (cryptoEngine == null) {
				logError("Property Item Descriptor: " + getItemDescriptor().getItemDescriptorName() + "." + getName()
						+ " not property configured.");
				throw new NullPointerException("Crypto Engine not configured "
						+ getItemDescriptor().getItemDescriptorName() + "." + this.getName());
			}
			try {
				return super.getPropertyValue(pItem, cryptoEngine.decrypt(pValue.toString()));
			} catch (Exception e) {
				return super.getPropertyValue(pItem, pValue);
			}
		}
	}

	/**
	 * Catch the attribute values that we care about and store them in member variables.
	 *
	 * @param pAttributeName
	 *            the Attribute to set
	 * @param pValue
	 *            the Value to set to the attribute
	 */
	public void setValue(final String pAttributeName, final Object pValue) {
		super.setValue(pAttributeName, pValue);
		if (pValue == null || pAttributeName == null) {
			return;
		}
		if (pAttributeName.equalsIgnoreCase(CRYPTO_ENGINE)) {
			try {
				this.mCryptoEngineName = (String) pValue;
			} catch (final ClassCastException cce) {
				logError("Invalid type for Crypto Engine", cce);
			}
		}
		if (pAttributeName.equalsIgnoreCase(ENCRYPT_ONLY)) {
			if (TRUE_STRING.equalsIgnoreCase((String) pValue)) {
				setEncryptOnly(true);
			}
		}
	}

	/**
	 * Logs an error for the repository we are part of.
	 *
	 * @param pError
	 *            The error string to log
	 */
	public void logError(final String pError) {
		logError(pError, null);
	}

	/**
	 * Log an error with an exception for the repository we are part of.
	 *
	 * @param pError
	 *            The error string to log
	 * @param pThrowable
	 *            The exception to log
	 */
	protected void logError(final String pError, final Throwable pThrowable) {
		if (getItemDescriptor() != null) {
			final RepositoryImpl repositoryImpl = (RepositoryImpl) getItemDescriptor().getRepository();
			if (repositoryImpl.isLoggingError()) {
				repositoryImpl.logError("Error with repository property: " + getName() + " item-descriptor "
						+ getItemDescriptor().getItemDescriptorName() + ": " + pError, pThrowable);
			}
		}
	}

	/**
	 * Logs a debug statement for the repository we are part of.
	 *
	 * @param pMessage
	 *            the Message to log
	 */
	public void logDebug(final String pMessage) {
		if (getItemDescriptor() != null) {
			final RepositoryImpl repositoryImpl = (RepositoryImpl) getItemDescriptor().getRepository();
			if (repositoryImpl.isLoggingDebug()) {
				repositoryImpl.logDebug("Repository property: " + getName() + " item-descriptor "
						+ getItemDescriptor().getItemDescriptorName() + ": " + pMessage);
			}
		}
	}

	/**
	 * Returns the name this type uses in the XML file.
	 *
	 * @return String The type for this property descriptor
	 */
	public String getTypeName() {
		return TYPE_NAME;
	}

	/**
	 * Gets the property type.
	 *
	 * @return java.lang.String
	 */
	public Class getPropertyType() {
		return java.lang.String.class;
	}

	/**
	 * Perform type checking.
	 *
	 * @param pClass
	 *            The class of this property (data type)
	 */
	public void setPropertyType(final Class pClass) {
		if (pClass != java.lang.String.class) {
			throw new IllegalArgumentException("encrypted properties must be java.lang.String");
		}
		super.setPropertyType(pClass);
	}

	/**
	 * Sets the component property type.
	 *
	 * @param pClass
	 *            the Component property type
	 */
	public void setComponentPropertyType(final Class pClass) {
		if (pClass != null) {
			throw new IllegalArgumentException("encrypted properties must be scalars");
		}
	}

	/**
	 * Sets the property item descriptor.
	 *
	 * @param pDesc
	 *            the Property Item Descriptor
	 */
	public void setPropertyItemDescriptor(final RepositoryItemDescriptor pDesc) {
		if (pDesc != null) {
			throw new IllegalArgumentException("encrypted properties must be java.lang.String");
		}
	}

	/**
	 * Sets the component item descriptor.
	 *
	 * @param pDesc
	 *            the Component Item Descriptor
	 */
	public void setComponentItemDescriptor(final RepositoryItemDescriptor pDesc) {
		if (pDesc != null) {
			throw new IllegalArgumentException("encrypted properties must be scalars");
		}
	}

	/**
	 * Checks if is encrypt only.
	 *
	 * @return true, if is encrypt only
	 */
	public boolean isEncryptOnly() {
		return mEncryptOnly;
	}

	/**
	 * Sets the encrypt only.
	 *
	 * @param pEncryptOnly
	 *            the new encrypt only
	 */
	public void setEncryptOnly(boolean pEncryptOnly) {
		mEncryptOnly = pEncryptOnly;
	}
}
