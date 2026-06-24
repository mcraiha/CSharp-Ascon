## About

Library for **Ascon-AEAD128** encryption/decryption, and **Ascon-Hash256** / **Ascon-XOF128** hashing

## How to use

Currently the basic API is similar to C based one. There is also a fancy API for easier operations.

❗ If you are using Ascon-AEAD128, do **NOT** reuse same key + nonce combination. Always change at least the nonce when you create a new encrypted message ❗

### C style API example

#### Ascon-AEAD128

```cs
using CSAscon;

// Message that will be encrypted 
byte[] message = System.Text.Encoding.UTF8.GetBytes("This message should be encrypted");

// Associated data
byte[] associatedData = System.Text.Encoding.UTF8.GetBytes("Associated data");

// Nonce (MUST be 16 bytes)
byte[] nonce = new byte[] { 206, 74, 86, 166, 217, 45, 90, 73, 240, 65, 165, 45, 215, 47, 94, 73 };

// Key (MUST be 16 bytes)
byte[] key = new byte[] { 101, 101, 174, 222, 224, 97, 156, 94, 123, 183, 109, 219, 208, 135, 104, 122 };

// Preallocate storage for encrypted data
byte[] encryptedMessage = new byte[message.Length + 16];

// Encrypt
int func_ret = Asconaead128.crypto_aead_encrypt(encryptedMessage, out int clen, message, message.Length, associatedData, associatedData.Length, null, nonce, key);

// Decrypt
byte[] decryptedMessage = new byte[message.Length];
func_ret = Asconaead128.crypto_aead_decrypt(decryptedMessage, out mlen2, null, encryptedMessage, clen, associatedData, associatedData.Length, nonce, key);
```

#### Ascon-Hash256

```cs
using CSAscon;

byte[] input = new byte[21] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21 };
byte[] outputHash = new byte[32];

// Hash
int returnValue = Asconhash256.crypto_hash(outputHash, input);
```
(the hash is always 32 bytes / 256 bits)

#### Ascon-XOF128

```cs
using CSAscon;

byte[] input = new byte[21] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21 };
int outputLength = 64;
byte[] outputHash = new byte[outputLength];
int returnValue = Asconxof128.crypto_hash(outputHash, input);
```

### Fancy API bytes example

#### Ascon-AEAD128

```cs
using CSAscon;

ReadOnlySpan<byte> message = "This is a very long and boring text for testing purposes 😀 !"u8;
ReadOnlySpan<byte> associatedData = "My associated data"u8;

ReadOnlySpan<byte> nonce = "MY_CAT_IS_NOT_IT"u8;
ReadOnlySpan<byte> key = "DO_NOT_USE_IN_PR"u8; // Use better key in real life

// Encrypt
byte[] encryptedMessage = Asconaead128.Encrypt(message, associatedData, nonce, key);

// Decrypt
byte[] decryptedMessage = Asconaead128.Decrypt(encryptedMessage, associatedData, nonce, key);
```

#### Ascon-Hash256

```cs
using CSAscon;

byte[] input = new byte[21] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21 };

// Hash
byte[] hash = Asconhash256.HashBytes(input);
```

(the hash is always 32 bytes / 256 bits)

#### Ascon-XOF128

```cs
using CSAscon;

byte[] input = new byte[21] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21 };
int outputLength = 64;

// Hash
byte[] hash = Asconxof128.HashBytes(input, outputLength);
```

### Fancy API stream example

#### Ascon-AEAD128

```cs
using CSAscon;

FileStream inputStream = File.OpenRead("fileToEncrypt.txt");
MemoryStream encryptedStream = new MemoryStream();

ReadOnlySpan<byte> associatedData = "My associated data"u8;
ReadOnlySpan<byte> nonce = "MY_CAT_IS_NOT_IT"u8;
ReadOnlySpan<byte> key = "DO_NOT_USE_IN_PR"u8; // Use better key in real life

// Encrypt
Asconaead128.Encrypt(inputStream, encryptedStream, associatedData, nonce, key);

// Decrypt
FileStream encryptedFileStream = File.OpenRead("mySecretFile.sec");
MemoryStream decryptedStream = new MemoryStream();
int shouldBeZero = Asconaead128.Decrypt(encryptedFileStream, decryptedStream, associatedData, nonce, key);
```

#### Ascon-Hash256

```cs
using CSAscon;

FileStream inputStream = File.OpenRead("holiday.jpg");

// Hash
byte[] hash = Asconhash256.HashBytes(inputStream);
```

(the hash is always 32 bytes / 256 bits)

#### Ascon-XOF128

```cs
using CSAscon;

FileStream inputStream = File.OpenRead("holiday.jpg");
int outputLength = 64;

// Hash
byte[] hash = Asconxof128.HashBytes(inputStream, outputLength);
```

### Fancy API stream async example

#### Ascon-AEAD128

```cs
using CSAscon;

FileStream inputStream = File.OpenRead("fileToEncrypt.txt");
MemoryStream encryptedStream = new MemoryStream();

ReadOnlySpan<byte> associatedData = "My associated data"u8;
ReadOnlySpan<byte> nonce = "MY_CAT_IS_NOT_IT"u8;
ReadOnlySpan<byte> key = "DO_NOT_USE_IN_PR"u8; // Use better key in real life

// Encrypt
await Asconaead128.EncryptAsync(inputStream, encryptedStream, associatedData, nonce, key);

// Decrypt
FileStream encryptedFileStream = File.OpenRead("mySecretFile.sec");
MemoryStream decryptedStream = new MemoryStream();
int shouldBeZero = await Asconaead128.DecryptAsync(encryptedFileStream, decryptedStream, associatedData, nonce, key);
```

#### Ascon-Hash256

```cs
using CSAscon;

FileStream inputStream = File.OpenRead("holiday.jpg");

// Hash
byte[] hash = await Asconhash256.HashBytesAsync(inputStream);
```

(the hash is always 32 bytes / 256 bits)

#### Ascon-XOF128

```cs
using CSAscon;

FileStream inputStream = File.OpenRead("holiday.jpg");
int outputLength = 64;

// Hash
byte[] hash = await Asconxof128.HashBytesAsync(inputStream, outputLength);
```