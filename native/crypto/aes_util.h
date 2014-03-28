#ifndef _JAVA_COM_FACEBOOK_CRYPTO_AES_UTIL_
#define _JAVA_COM_FACEBOOK_CRYPTO_AES_UTIL_

#include <jni.h>
#include <openssl/evp.h>

extern const int AES_ENCRYPT_MODE;
extern const int AES_DECRYPT_MODE;

void Init_AES_CTX_Ptr_Field(JNIEnv* env);

int Init_AES(JNIEnv* env, jobject obj, jbyteArray key, jbyteArray iv, int mode);

EVP_CIPHER_CTX* Create_AES_JNI_CTX();

EVP_CIPHER_CTX* Get_AES_JNI_CTX(JNIEnv* env, jobject obj);

EVP_CIPHER_CTX* Get_Cipher_CTX(JNIEnv* env, jobject obj);

void Set_AES_JNI_CTX(JNIEnv* env, jobject obj, EVP_CIPHER_CTX* ctx);

void Destroy_AES_JNI_CTX(EVP_CIPHER_CTX* ctx);

#endif // _JAVA_COM_FACEBOOK_CRYPTO_AES_UTIL_

