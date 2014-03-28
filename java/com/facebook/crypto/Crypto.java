/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

import android.annotation.SuppressLint;
import com.facebook.crypto.cipher.NativeAESCipher;
import com.facebook.crypto.cipher.NativeAESCipherException;
import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.streams.NativeAESCipherInputStream;
import com.facebook.crypto.util.NativeCryptoLibrary;
import com.facebook.crypto.util.SystemNativeCryptoLibrary;

public enum Crypto {
	INSTANCE;

  private final NativeCryptoLibrary mNativeCryptoLibrary;

  public static Crypto getInstance(){
      return Crypto.INSTANCE;
  }
  
  Crypto() {
    mNativeCryptoLibrary = SystemNativeCryptoLibrary.getInstance();
  }

  /**
   * Tells if crypto native library and this class can be used.
   * @return true if and only if libraries could be loaded successfully.
   */
  public boolean isAvailable() {
    try {
      mNativeCryptoLibrary.ensureCryptoLoaded();
      return true;
    } catch (Throwable t) {
      return false;
    }
  }

  /**
   * Gives you an output stream wrapper that encrypts the text written.
   *
   * @param cipherStream The stream that the encrypted data will be written to.
   * @param entity A unique object identifying what is being written.
   *
   * @return A ciphered output stream to write to.
   * @throws CryptoInitializationException 
   * @throws NativeAESCipherException 
   * @throws IOException
   */
  public InputStream getAESCipherInputStream(InputStream cipherStream, byte[] iv, byte[] key) throws NativeAESCipherException, CryptoInitializationException {
	  
    NativeAESCipher cipher = new NativeAESCipher(mNativeCryptoLibrary);
    cipher.encryptInit(key, iv);
    return new NativeAESCipherInputStream(cipherStream, cipher);

  }

  /**
   * Gives you an input stream wrapper that decrypts another stream.
   * You must read the whole stream to completion, i.e. till -1. Failure
   * to do so may result in a security vulnerability.
   *
   * @param cipherStream The stream from which the encrypted data is read.
   * @param entity A unique object identifying what is being read.
   *
   * @return A ciphered input stream to read from.
   * @throws NativeAESCipherException 
   * @throws IOException
   * @throws CryptoInitializationException Thrown if the crypto libraries could not be initialized.
   */
  public InputStream getAESDecipherInputStream(InputStream cipherStream,  byte[] iv, byte[] key) throws NativeAESCipherException, CryptoInitializationException {
	    NativeAESCipher cipher = new NativeAESCipher(mNativeCryptoLibrary);
	    cipher.decryptInit(key, iv);
	    return new NativeAESCipherInputStream(cipherStream, cipher);
  }
  
  @SuppressLint("TrulyRandom")
  /**
   * Generates a random IV
   * NOTE: SecureRandom is flawed on several versions of Android, iv are not usually considered a secret so there should be no problem with 
   * that but be sure that is OK for your system. 
   * @param iv A byte array of the desired length to receive the iv 
   */
  public static void generateRandomIV (byte[] iv) {
	  SecureRandom sr = new SecureRandom();	
	  sr.nextBytes(iv);	  
  }


}
