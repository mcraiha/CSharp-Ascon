# CSharp-Ascon

Managed C# (CSharp) implementation of [Ascon](https://ascon.iaik.tugraz.at/index.html) (Ascon-AEAD128, Ascon-Hash256 and Ascon-XOF128). Ascon is standardized as NIST SP 800-232: https://csrc.nist.gov/pubs/sp/800/232/final

## Build status

[![.NET](https://github.com/mcraiha/CSharp-Ascon/actions/workflows/dotnet.yml/badge.svg)](https://github.com/mcraiha/CSharp-Ascon/actions/workflows/dotnet.yml)

## Nuget

[LibAscon128](https://www.nuget.org/packages/LibAscon128)

## Why

I needed a weekend project for myself

## How to use

Currently the basic API is similar to C based one. There is also a fancy API for easier operations.

Ascon-AEAD128, Ascon-Hash256 and Ascon-XOF128 are implemented in standalone files, so you can copy any one of those to your project and just use it.

❗If you are using Ascon-AEAD128, do **NOT** reuse same key + nonce combination. Always change at least the nonce when you create a new encrypted message ❗

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

### Fancy API example

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

## Porting story

Code is ported from **opt64** versions of the C code. So all methods operate 8 bytes (64 bits) at time.

## Limitations

Only [little-endian](https://en.wikipedia.org/wiki/Endianness) (LE) systems (x86, x64, ARM etc.) are supported, because there aren't that many big-endian .NET environments.

## Benchmarks

You can run benchmarks by moving to **benchmarks** folder and running following command
```bash
dotnet run -c Release
```

there are four different input sizes (64 bytes, 1024 bytes, 65536 bytes and 1 MiB) and comparisons are done between Ascon-128 and Ascon-128a

Below is one run of the benchmark  
```
BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.8457/25H2/2025Update/HudsonValley2)
AMD Ryzen 5 7600 3.80GHz, 1 CPU, 12 logical and 6 physical cores
.NET SDK 10.0.100
  [Host]     : .NET 10.0.0 (10.0.0, 10.0.25.52411), X64 RyuJIT x86-64-v4
  DefaultJob : .NET 10.0.0 (10.0.0, 10.0.25.52411), X64 RyuJIT x86-64-v4


| Method                        | Mean           | Error        | StdDev       | Gen0   | Allocated |
|------------------------------ |---------------:|-------------:|-------------:|-------:|----------:|
| Encrypt_64bytes_Ascon128      |       651.2 ns |      5.57 ns |      4.65 ns | 0.0057 |     104 B |
| Encrypt_1024bytes_Ascon128    |     5,474.4 ns |      7.36 ns |      5.75 ns |      - |     104 B |
| Encrypt_65536bytes_Ascon128   |   330,002.3 ns |  1,648.61 ns |  1,376.67 ns |      - |     104 B |
| Encrypt_1048576bytes_Ascon128 | 5,267,676.1 ns | 17,209.34 ns | 14,370.58 ns |      - |     104 B |

```

## License

[CC0 1.0 Universal](LICENSE) because original C implementation uses that license

Original [genkat](https://github.com/ascon/ascon-c/blob/main/tests/genkat_aead.c) uses NIST license, so tests in this project are modified from it. 

The tests vector files (**LWC_AEAD_KAT_128_128.txt**, **LWC_XOF_KAT_128_512.txt** and **LWC_HASH_KAT_128_256.txt**) are also generated with genkat tool.
