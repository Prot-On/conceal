/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <aes_util.h>
#include <jni.h>
#include <openssl/evp.h>
#include <util.h>

static const int AES_CIPHER_BLOCK_SIZE_BYTES = 16;

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeAESCipher_nativeDestroy(
  JNIEnv* env,
  jobject obj) {
  clearContext(env, obj);
  return CRYPTO_SUCCESS;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeAESCipher_nativeEncryptInit(
  JNIEnv* env,
  jobject obj,
  jbyteArray key,
  jbyteArray iv) {

  if (!Init_AES(env, obj, key, iv, AES_ENCRYPT_MODE)) {
    return CRYPTO_FAILURE;
  }
  
  return CRYPTO_SUCCESS;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeAESCipher_nativeDecryptInit(
  JNIEnv* env,
  jobject obj,
  jbyteArray key,
  jbyteArray iv) {

  if (!Init_AES(env, obj, key, iv, AES_DECRYPT_MODE)) {
    return CRYPTO_FAILURE;
  }

  return CRYPTO_SUCCESS;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeAESCipher_nativeUpdate(
  JNIEnv* env,
  jobject obj,
  jbyteArray data,
  jint offset,
  jint dataLength,
  jbyteArray output) {

  int bytesWritten = 0;
  EVP_CIPHER_CTX* ctx = Get_Cipher_CTX(env, obj);
  if (!ctx) {
    return CRYPTO_NO_BYTES_WRITTEN;
  }
	
  jbyte* outputBytes = (*env)->GetByteArrayElements(env, output, NULL);
  if (!outputBytes) {
    return CRYPTO_NO_BYTES_WRITTEN;
  }

  jbyte* dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
  if (!dataBytes) {
    (*env)->ReleaseByteArrayElements(env, output, outputBytes, JNI_ABORT);
    return CRYPTO_NO_BYTES_WRITTEN;
  }

  bytesWritten = dataLength;
  if (!EVP_CipherUpdate(ctx, outputBytes, &bytesWritten, dataBytes + offset, dataLength)) {
    bytesWritten = CRYPTO_NO_BYTES_WRITTEN;
  }
  
  (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);
  
  return bytesWritten;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeAESCipher_nativeFinal(
  JNIEnv* env,
  jobject obj,
  jbyteArray output) {

  int bytesWritten = 0;

  EVP_CIPHER_CTX* ctx = Get_Cipher_CTX(env, obj);
  if (!ctx) {
    return CRYPTO_NO_BYTES_WRITTEN;
  }
  
  jbyte* outputBytes = (*env)->GetByteArrayElements(env, output, NULL);
  if (!outputBytes) {
    return CRYPTO_NO_BYTES_WRITTEN;
  }
  if (!EVP_CipherFinal_ex(ctx, outputBytes, &bytesWritten)) {
    bytesWritten = CRYPTO_NO_BYTES_WRITTEN;
  }

  (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);
  //clearContext(env, obj);

  return bytesWritten;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeAESCipher_nativeGetCipherBlockSize(
  JNIEnv* env) {

  return AES_CIPHER_BLOCK_SIZE_BYTES;
}

// Give the java layer access to C constants.
JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeAESCipher_nativeFailure(
  JNIEnv* env,
  jobject obj) {

  return CRYPTO_FAILURE;
}
