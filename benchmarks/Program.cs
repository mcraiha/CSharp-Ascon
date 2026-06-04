using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

using CSAscon;

namespace benchmarks;

[MemoryDiagnoser]
public class Asconaead128Bench
{
	// Keys and nonces
	private byte[] key128 = new byte[Asconaead128.CRYPTO_KEYBYTES] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 64, 100, 200, 225, 255 };
  	private byte[] nonce128 = new byte[Asconaead128.CRYPTO_NPUBBYTES] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13 };

	// Associated data
	private static readonly byte[] ad = new byte[15] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };

	// Messages (these are filled in constructor)
	private byte[] msg64 = new byte[64];
	private byte[] msg1024 = new byte[1024];
	private byte[] msg65536 = new byte[65536];
	private byte[] msg1048576 = new byte[1048576];

	// Store encypted bytes
	private byte[] encrypted64 = new byte[64 + Asconaead128.CRYPTO_ABYTES];
	private byte[] encrypted1024 = new byte[1024 + Asconaead128.CRYPTO_ABYTES];
	private byte[] encrypted65536 = new byte[65536 + Asconaead128.CRYPTO_ABYTES];
	private byte[] encrypted1048576 = new byte[1048576 + Asconaead128.CRYPTO_ABYTES];

	public Asconaead128Bench()
	{
		Random rnd = new Random();
		rnd.NextBytes(msg64);
		rnd.NextBytes(msg1024);
		rnd.NextBytes(msg65536);
		rnd.NextBytes(msg1048576);
	}

	// 64 bytes message
	[Benchmark]
	public int Encrypt_64bytes_Ascon128() => Asconaead128.crypto_aead_encrypt(encrypted64, out _, msg64, msg64.Length, ad, ad.Length, null, nonce128, key128);

	// 1024 bytes message
	[Benchmark]
	public int Encrypt_1024bytes_Ascon128() => Asconaead128.crypto_aead_encrypt(encrypted1024, out _, msg1024, msg1024.Length, ad, ad.Length, null, nonce128, key128);

	// 65536 bytes message
	[Benchmark]
	public int Encrypt_65536bytes_Ascon128() => Asconaead128.crypto_aead_encrypt(encrypted65536, out _, msg65536, msg65536.Length, ad, ad.Length, null, nonce128, key128);

	// 1048576 bytes message
	[Benchmark]
	public int Encrypt_1048576bytes_Ascon128() => Asconaead128.crypto_aead_encrypt(encrypted1048576, out _, msg1048576, msg1048576.Length, ad, ad.Length, null, nonce128, key128);
}

class Program
{
	static void Main(string[] args)
	{
		var summary = BenchmarkRunner.Run<Asconaead128Bench>();
	}
}
