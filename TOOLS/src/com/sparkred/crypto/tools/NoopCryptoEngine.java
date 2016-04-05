/*
 * Please read the README.md and LICENSE.md files contained in this repository or module.
 *
 * Please contact sales@sparkred.com or support@sparkred.com if you have any questions.
 *
 * This code is copyright Spark::red https://www.sparkred.com 2007-2016, all right reserved.
 */
package com.sparkred.crypto.tools;

import atg.nucleus.GenericService;

/**
 * The Class NoopCryptoEngine provides a noop decryptor to be used by the ReKey engine to batch encrypt plaintext data.
 */
public class NoopCryptoEngine extends GenericService {

	/**
	 * Decrypt. This method just returns the same text.
	 *
	 * @param pEncryptedText
	 *            the encrypted text
	 * @return the string
	 */
	public String decrypt(String pEncryptedText) {
		return pEncryptedText;
	}

}
