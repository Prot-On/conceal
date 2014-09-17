##What is Conceal?##
Conceal provides a set of Java APIs to perform cryptography on Android. 
It was designed to be able to encrypt large files on disk in a fast and 
memory efficient manner. 

The major target for this project is typical Android devices which run old 
Android versions, have low memory and slower processors.

Unlike other libraries, which provide a Smorgasbord of encryption algorithms 
and options, Conceal prefers to abstract this choice and use sane defaults. 
Thus Conceal is not a general purpose crypto library, however it aims to provide 
useful functionality.

##Why this fork?##

This modified version of Conceal just includes 1 algorithm, AES CBC with standard 
padding PKCS#5, instead of AES GCM and HMAC-SHA1.

Depending on the key size it will use the correct AES version (16 bytes - AES 128, 
24 - AES 192, 32 - AES 256), remember that iv have always the same size 16 bytes.

This library is geared to being used with streams, both Cipher and decipher is done
via InputStreams but it should be easy to port it to OutputStreams if needed.

BetterCipherInputStream is a sort of CipherStream but greatly improves the speed of 
any cipher used with it, it is almost the same as the main Conceal one but added support
for padded ciphers.

Test and benchmarks has not been ported and as Buck is not compatible with windows, 
the build system would not work.

##Quick start##


####Use prebuilt libraries####
Just download and add to your proyect the prebuilt libraries from the [release folder](release)


####Building java libaries####
```bash
gradle build
```

####Building native libaries####
```bash
cd /native/crypto
ndk-build APP_BUILD_SCRIPT=Android.mk APP_ABI=all NDK_PROJECT_PATH=.
```

######An aside on KitKat######
> Conceal predates Jellybean 4.3. On KitKat, Android changed the provider for 
> cryptographic algorithms to OpenSSL. The default Cipher stream however still 
> does not perform well. When replaced with our Cipher stream 
> (see BetterCipherInputStream), the default implementation is competitive against 
> Conceal. On older phones, Conceal is faster than the system provided libraries.


##Usage##

####Encryption###
```java
// Creates a new Crypto object with default implementations of 
// a key chain as well as native library.
Crypto crypto = Crypto.getInstance();

// Check for whether the crypto functionality is available
// This might fail if Android does not load libaries correctly.
if (!crypto.isAvailable()) {
  return;
}

OutputStream fileStream = new BufferedInputStream(
  new FileOutputStream(file));

// Creates an input stream which encrypts the data as
// it is read from it.
InputStream inputStream = crypto.getAESCipherInputStream(
  fileStream, iv, key);

// Read into a byte array.
int read;
byte[] buffer = new byte[1024];
  
// You must read the entire stream to completion.
// Due to padding and stream internals it is not possible to
// read the stream in one go.
while ((read = inputStream.read(buffer)) != -1) {
  out.write(buffer, 0, read);
}
```

####Decryption####
```java
// Get the file to which ciphertext has been written.
FileInputStream fileStream = new FileInputStream(file);

// Creates an input stream which decrypts the data as
// it is read from it.
InputStream inputStream = crypto.getAESDecipherInputStream(
  fileStream, iv, key);

// Read into a byte array.
int read;
byte[] buffer = new byte[1024];

// You must read the entire stream to completion.
// Due to padding and stream internals it is not possible to
// read the stream in one go.
while ((read = inputStream.read(buffer)) != -1) {
  out.write(buffer, 0, read);
}

inputStream.close();
```

