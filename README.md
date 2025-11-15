# CSharp-Ascon

Managed C# (CSharp) implementation of [Ascon](https://ascon.iaik.tugraz.at/index.html) (Ascon-128 and Ascon-128a)

## Build status

[![.NET](https://github.com/mcraiha/CSharp-Ascon/actions/workflows/dotnet.yml/badge.svg)](https://github.com/mcraiha/CSharp-Ascon/actions/workflows/dotnet.yml)

## Nuget

[LibAscon128](https://www.nuget.org/packages/LibAscon128)

## Why

I needed a weekend project for myself

## How to use

Currently the basic API is similar to C based one. There is also a fancy API for easier operations.

Both Ascon-128 (Ascon128v12.cs) and Ascon-128a (Ascon128av12.cs) are standalone files, so you can copy either one of them to your project and just use it.

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

With Ascon-128 you can do the following, test it out in [.NET Fiddle](https://dotnetfiddle.net/AAkKSV)

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

## Porting story

Code is ported from [opt64](https://github.com/ascon/ascon-c/tree/main/crypto_aead/ascon128v12/opt64) version of the C code version. So it operates 8 bytes (64 bits) at time.

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
BenchmarkDotNet v0.15.6, Windows 11 (10.0.26200.7171)
AMD Ryzen 5 7600 3.80GHz, 1 CPU, 12 logical and 6 physical cores
.NET SDK 10.0.100
  [Host]     : .NET 10.0.0 (10.0.0, 10.0.25.52411), X64 RyuJIT x86-64-v4
  DefaultJob : .NET 10.0.0 (10.0.0, 10.0.25.52411), X64 RyuJIT x86-64-v4


| Method                         | Mean           | Error        | StdDev       | Median         | Gen0     | Allocated |
|------------------------------- |---------------:|-------------:|-------------:|---------------:|---------:|----------:|
| Encrypt_64bytes_Ascon128       |       869.5 ns |     17.41 ns |     33.54 ns |       860.9 ns |   0.0248 |     424 B |
| Encrypt_64bytes_Ascon128a      |       685.6 ns |     13.74 ns |     22.58 ns |       676.7 ns |   0.0248 |     424 B |
| Encrypt_1024bytes_Ascon128     |     8,011.3 ns |    158.78 ns |    290.35 ns |     7,874.0 ns |   0.2441 |    4264 B |
| Encrypt_1024bytes_Ascon128a    |     6,048.7 ns |    120.17 ns |    204.05 ns |     5,953.9 ns |   0.2518 |    4264 B |
| Encrypt_65536bytes_Ascon128    |   496,623.4 ns |  9,904.56 ns | 15,709.69 ns |   506,071.8 ns |  15.6250 |  262312 B |
| Encrypt_65536bytes_Ascon128a   |   380,408.0 ns |  7,507.10 ns | 12,747.62 ns |   373,787.5 ns |  15.6250 |  262312 B |
| Encrypt_1048576bytes_Ascon128  | 7,540,029.7 ns | 19,189.49 ns | 16,024.09 ns | 7,542,664.1 ns | 250.0000 | 4194472 B |
| Encrypt_1048576bytes_Ascon128a | 5,305,783.6 ns | 31,367.81 ns | 26,193.55 ns | 5,294,858.6 ns | 250.0000 | 4194472 B |

```

## License

[CC0 1.0 Universal](LICENSE) because original C implementation uses that license

Original [genkat](https://github.com/ascon/ascon-c/blob/main/tests/genkat_aead.c) uses NIST license, so tests in this project are modified from it. 

The tests vector files (**LWC_AEAD_KAT_128_128.txt** and **LWC_AEAD_KAT_128_128_a.txt**) are also generated with genkat tool.
