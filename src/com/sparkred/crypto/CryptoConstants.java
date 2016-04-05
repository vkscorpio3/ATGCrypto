/*
 * Please read the README.md and LICENSE.md files contained in this repository or module.
 *
 * Please contact sales@sparkred.com or support@sparkred.com if you have any questions.
 *
 * This code is copyright Spark::red https://www.sparkred.com 2007-2016, all right reserved.
 */
package com.sparkred.crypto;

/**
 * The Class CryptoConstants.
 *
 * This class has constants for things like Repository Item Descriptor and Property names, and similar Strings.
 */
public class CryptoConstants {

	/** The Constant for the strong symmetric encryption algorithm to use. */
	public static final String STRONG_ALGO = "PBEWITHSHA256AND256BITAES-CBC-BC";

	/** The Constant BOUNCY_CASTLE_PROVIDER_NAME. */
	public static final String BOUNCY_CASTLE_PROVIDER_NAME = "BC";

	/** The Constant for the ATG repository item descriptor name used for the Crypto Engine configurations. */
	public static final String CRYPTO_ENGINE_ITEM_DESC = "cryptoEngine";

	/** The Constant for the ATG repository cryptoEngine item's property name for the encrypted data key. */
	public static final String ENC_DATA_KEY_PROP_NAME = "encDataKey";

	/** The Constant for the ATG repository cryptoEngine item's property name for the description of the Engine. */
	public static final String DESCRIPTION_PROP_NAME = "description";

	/**
	 * The Constant for the ATG repository cryptoEngine item's property name for the encrypted data key's creation date,
	 * used for expiration notifications.
	 */
	public static final String KEY_DATE_PROP_NAME = "keyDate";

}
