/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
package com.facebook.crypto.cipher;

import java.util.Locale;

import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.util.Assertions;
import com.facebook.crypto.util.NativeCryptoLibrary;
import com.facebook.proguard.annotations.DoNotStrip;

/**
 * Various native functions to encrypt/decrypt data using AES.
 */
@DoNotStrip
public class NativeAESCipher {

  public static final String FAILURE = "Failure";

  private static final String CIPHER_ALREADY_INIT = "Cipher has already been initialized";
  private static final String CIPHER_NOT_INIT = "Cipher has not been initialized";
  private static final String CIPHER_NOT_FINALIZED = "Cipher has not been finalized";

  public static final int IV_LENGTH = 16;
  public static int nativeFailure = 42;

  private STATE mCurrentState = STATE.UNINITIALIZED;

  private final NativeCryptoLibrary mNativeCryptoLibrary;

  private enum STATE {
    UNINITIALIZED,
    INITIALIZED,
    FINALIZED
  };

  public NativeAESCipher(NativeCryptoLibrary nativeCryptoLibrary) {
    mNativeCryptoLibrary = nativeCryptoLibrary;
  }

  public void encryptInit(byte[] key, byte[] iv)
      throws NativeAESCipherException, CryptoInitializationException {
    Assertions.checkState(mCurrentState == STATE.UNINITIALIZED, CIPHER_ALREADY_INIT);
    mNativeCryptoLibrary.ensureCryptoLoaded();
    if (nativeFailure == 42) {
    	nativeFailure = nativeFailure();
    }
    if (nativeEncryptInit(key, iv) == nativeFailure) {
      throw new NativeAESCipherException("encryptInit");
    }
    mCurrentState = STATE.INITIALIZED;
  }
  public void decryptInit(byte[] key, byte[] iv)
      throws NativeAESCipherException, CryptoInitializationException {
    Assertions.checkState(mCurrentState == STATE.UNINITIALIZED, CIPHER_ALREADY_INIT);
    mNativeCryptoLibrary.ensureCryptoLoaded();
    if (nativeFailure == 42) {
    	nativeFailure = nativeFailure();
    }   
    if (nativeDecryptInit(key, iv) == nativeFailure) {
      throw new NativeAESCipherException("decryptInit");
    }
    mCurrentState = STATE.INITIALIZED;
  }

  public int update(byte[] data, int offset, int dataLen, byte[] output)
      throws NativeAESCipherException {
    ensureInInitalizedState();
    int bytesRead = nativeUpdate(data, offset, dataLen, output);
    if (bytesRead < 0) {
      throw new NativeAESCipherException(
          formatStrLocaleSafe(
              "update: Offset = %d; DataLen = %d; Result = %d",
              offset,
              dataLen,
              bytesRead));
    }
    return bytesRead;
  }

  public int doFinal(byte[] data)
      throws NativeAESCipherException {
	ensureInInitalizedState();
    mCurrentState = STATE.FINALIZED;
    int bytesRead = nativeFinal(data);
    if (bytesRead < 0) {
      throw new NativeAESCipherException("encryptFinal");
    }
    return bytesRead;
  }


  public void destroy() throws NativeAESCipherException {
    ensureInFinalizedState();
    if (nativeDestroy() == nativeFailure) {
      throw new NativeAESCipherException("destroy");
    }
    mCurrentState = STATE.UNINITIALIZED;
  }

  public int getCipherBlockSize() {
    ensureInInitalizedState();
    return nativeGetCipherBlockSize();
  }

  private void ensureInInitalizedState() {
    boolean initialized =
        mCurrentState == STATE.INITIALIZED;
    Assertions.checkState(initialized, CIPHER_NOT_INIT);
  }

  private void ensureInFinalizedState() {
    boolean finalized =
        mCurrentState == STATE.FINALIZED;
    Assertions.checkState(finalized, CIPHER_NOT_FINALIZED);
  }

  private String formatStrLocaleSafe(String format, Object... args) {
    return String.format((Locale)null, format, args);
  }

  // Used to store the AES cipher context.
  @DoNotStrip
  private int mCtxPtr;

  // The integer value representing failure in JNI world.
  private static native int nativeFailure();

  private native int nativeEncryptInit(byte[] key, byte[] iv);
  private native int nativeDecryptInit(byte[] key, byte[] iv);

  private native int nativeUpdate(byte[] data, int offset, int dataLen, byte[] output);

  private native int nativeFinal(byte[] output);

  private native int nativeDestroy();

  private native int nativeGetCipherBlockSize();
}
