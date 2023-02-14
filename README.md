# CSharp-Ascon

Managed C# (CSharp) implementation of [Ascon](https://ascon.iaik.tugraz.at/index.html) (Ascon-128 and Ascon-128a)

## Why

I needed a weekend project for myself

## How to use

Currently the API is similar to C based one. I will create a simpler one in the future.

Both Ascon-128 (Ascon128v12.cs) and Ascon-128a (Ascon128av12.cs) are standalone files, so you can copy either one of them to your project and just use it. Nuget package will arrive later on.

## Porting story

Code is ported from [opt64](https://github.com/ascon/ascon-c/tree/main/crypto_aead/ascon128v12/opt64) version of the C code version. So it operates 8 bytes (64 bits) at time.

## Limitations

Only [little-endian](https://en.wikipedia.org/wiki/Endianness) (LE) systems (x86, x64, ARM etc.) are supported, because there aren't that many big-endian .NET environments.

## License

[CC0 1.0 Universal](LICENSE) because original C implementation uses that license

Original [genkat](https://github.com/ascon/ascon-c/blob/main/tests/genkat_aead.c) uses NIST license, so tests in this project are modified from it. 

The tests vector files (**LWC_AEAD_KAT_128_128.txt** and **LWC_AEAD_KAT_128_128_a.txt**) are also generated with genkat tool.
