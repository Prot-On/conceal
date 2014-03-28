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
#include <util.h>

// Used globally.
const int AES_ENCRYPT_MODE = 1;
const int AES_DECRYPT_MODE = 0;

static const char* JAVA_AES_CLASS = "com/facebook/crypto/cipher/NativeAESCipher";

static const int AES_KEY_LENGTH_IN_BYTES = 16;
static const int AES_IV_LENGTH_IN_BYTES = 16;

// Cache field id.
static jfieldID fieldId = NULL;

void Init_AES_CTX_Ptr_Field(JNIEnv* env) {
  if (!fieldId) {
    jclass AESClass = (*env)->FindClass(env, JAVA_AES_CLASS);
    fieldId = (*env)->GetFieldID(env, AESClass, "mCtxPtr", "I");
  }
}

int Init_AES(JNIEnv* env, jobject obj, jbyteArray key, jbyteArray iv, int mode) {
  jbyte* keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
  if (!keyBytes) {
    return CRYPTO_FAILURE;
  }

  jbyte* ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
  if (!ivBytes) {
    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    return CRYPTO_FAILURE;
  }

  int keyLength = (*env)->GetArrayLength( env, key );
  
  EVP_CIPHER_CTX* ctx = Create_AES_JNI_CTX();
  Set_AES_JNI_CTX(env, obj, ctx);

  switch(keyLength) {
		case 16:
			if (!EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, keyBytes, ivBytes, mode)) {
				return CRYPTO_FAILURE;
			}
		break;
		case 24:
			if (!EVP_CipherInit_ex(ctx, EVP_aes_192_cbc(), NULL, keyBytes, ivBytes, mode)) {
				return CRYPTO_FAILURE;
			}
		break;
		case 32:
			if (!EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, keyBytes, ivBytes, mode)) {
				return CRYPTO_FAILURE;
			}
		break;
  }		
  (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
  return CRYPTO_SUCCESS;
}

EVP_CIPHER_CTX* Create_AES_JNI_CTX() {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return NULL;
  }
  return ctx;
}

EVP_CIPHER_CTX* Get_Cipher_CTX(JNIEnv* env, jobject obj) { 
  EVP_CIPHER_CTX* jniCtxPtr = (EVP_CIPHER_CTX*) Get_JNI_CTX(env, obj, fieldId);
  if (!jniCtxPtr) {
    return NULL;
  }
  return jniCtxPtr;
}

void Set_AES_JNI_CTX(JNIEnv* env, jobject obj, EVP_CIPHER_CTX* ctx) {
  Set_JNI_CTX(env, obj, fieldId, (jint) ctx);
}

void clearContext(JNIEnv* env, jobject obj) {
  EVP_CIPHER_CTX* ctx = Get_Cipher_CTX(env, obj);
  if (!ctx) {
    return;
  }
  EVP_CIPHER_CTX_free(ctx);
  Set_AES_JNI_CTX(env, obj, 0);
}

