# CSharp-Ascon

Managed C# (CSharp) implementation of [Ascon](https://ascon.iaik.tugraz.at/index.html) (Ascon-128 and Ascon-128a)

## Build status

[![.NET](https://github.com/mcraiha/CSharp-Ascon/actions/workflows/dotnet.yml/badge.svg)](https://github.com/mcraiha/CSharp-Ascon/actions/workflows/dotnet.yml)

## Why

I needed a weekend project for myself

## How to use

Currently the basic API is similar to C based one. There is also a fancy API for easier operations.

Both Ascon-128 (Ascon128v12.cs) and Ascon-128a (Ascon128av12.cs) are standalone files, so you can copy either one of them to your project and just use it. Nuget package will arrive later on.

### C style API example

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

## Porting story

Code is ported from [opt64](https://github.com/ascon/ascon-c/tree/main/crypto_aead/ascon128v12/opt64) version of the C code version. So it operates 8 bytes (64 bits) at time.

## Limitations

Only [little-endian](https://en.wikipedia.org/wiki/Endianness) (LE) systems (x86, x64, ARM etc.) are supported, because there aren't that many big-endian .NET environments.

## License

[CC0 1.0 Universal](LICENSE) because original C implementation uses that license

Original [genkat](https://github.com/ascon/ascon-c/blob/main/tests/genkat_aead.c) uses NIST license, so tests in this project are modified from it. 

The tests vector files (**LWC_AEAD_KAT_128_128.txt** and **LWC_AEAD_KAT_128_128_a.txt**) are also generated with genkat tool.
