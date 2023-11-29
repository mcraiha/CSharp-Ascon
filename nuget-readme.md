## About

Library for Ascon-128 and Ascon-128a encryption/decryption

## How to use

Currently the basic API is similar to C based one. There is also a fancy API for easier operations.

❗ Do **NOT** reuse same key + nonce combination. Always change at least the nonce when you create a new encrypted message ❗

### C style API example

With Ascon-128 you can do the following

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
int func_ret = Ascon128v12.crypto_aead_encrypt(encryptedMessage, out int clen, message, message.Length, associatedData, associatedData.Length, null, nonce, key);

// Decrypt
byte[] decryptedMessage = new byte[message.Length];
func_ret = Ascon128v12.crypto_aead_decrypt(decryptedMessage, out mlen2, null, encryptedMessage, clen, associatedData, associatedData.Length, nonce, key);
```

with Ascon-128a you can do the following

```cs
using CSAscon;

// Message that will be encrypted 
byte[] message = System.Text.Encoding.UTF8.GetBytes("This message should be encrypted");

// Associated data
byte[] associatedData = System.Text.Encoding.UTF8.GetBytes("Associated data");

// Nonce (MUST be 16 bytes)
byte[] nonce = new byte[] { 6, 74, 86, 166, 217, 45, 90, 73, 241, 65, 165, 45, 215, 47, 94, 73 };

// Key (MUST be 16 bytes)
byte[] key = new byte[] { 11, 101, 174, 222, 224, 97, 156, 94, 123, 13, 109, 219, 208, 15, 14, 122 };

// Preallocate storage for encrypted data
byte[] encryptedMessage = new byte[message.Length + 16];

// Encrypt
int func_ret = Ascon128av12.crypto_aead_encrypt(encryptedMessage, out int clen, message, message.Length, associatedData, associatedData.Length, null, nonce, key);

// Decrypt
byte[] decryptedMessage = new byte[message.Length];
func_ret = Ascon128av12.crypto_aead_decrypt(decryptedMessage, out mlen2, null, encryptedMessage, clen, associatedData, associatedData.Length, nonce, key);
```

### Fancy API example

With Ascon-128 you can do the following

```cs
using CSAscon;

ReadOnlySpan<byte> message = "This is a very long and boring text for testing purposes 😀 !"u8;
ReadOnlySpan<byte> associatedData = "My associated data"u8;

ReadOnlySpan<byte> nonce = "MY_CAT_IS_NOT_IT"u8;
ReadOnlySpan<byte> key = "DO_NOT_USE_IN_PR"u8; // Use better key in real life

// Encrypt
byte[] encryptedMessage = Ascon128v12.Encrypt(message, associatedData, nonce, key);

// Decrypt
byte[] decryptedMessage = Ascon128v12.Decrypt(encryptedMessage, associatedData, nonce, key);
```

With Ascon-128a you can do the following

```cs
using CSAscon;

ReadOnlySpan<byte> message = "This is a very long and boring text for testing purposes 😀 !"u8;
ReadOnlySpan<byte> associatedData = "My associated data"u8;

ReadOnlySpan<byte> nonce = "MY_CAT_IS_NOT_IT"u8;
ReadOnlySpan<byte> key = "DO_NOT_USE_IN_PR"u8; // Use better key in real life

// Encrypt
byte[] encryptedMessage = Ascon128av12.Encrypt(message, associatedData, nonce, key);

// Decrypt
byte[] decryptedMessage = Ascon128av12.Decrypt(encryptedMessage, associatedData, nonce, key);
```