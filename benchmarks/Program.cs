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

[MemoryDiagnoser]
public class Asconhash256Bench
{
	// Messages (these are filled in constructor)
	private byte[] msg64 = new byte[64];
	private byte[] msg1024 = new byte[1024];
	private byte[] msg65536 = new byte[65536];
	private byte[] msg1048576 = new byte[1048576];

	public Asconhash256Bench()
	{
		Random rnd = new Random();
		rnd.NextBytes(msg64);
		rnd.NextBytes(msg1024);
		rnd.NextBytes(msg65536);
		rnd.NextBytes(msg1048576);
	}

	// 64 bytes message
	[Benchmark]
	public byte[] Hash64Bytes() => Asconhash256.HashBytes(msg64);

	// 1024 bytes message
	[Benchmark]
	public byte[] Hash1024Bytes() => Asconhash256.HashBytes(msg1024);

	// 65536 bytes message
	[Benchmark]
	public byte[] Hash65536Bytes() => Asconhash256.HashBytes(msg65536);

	// 1048576 bytes message
	[Benchmark]
	public byte[] Hash1048576Bytes() => Asconhash256.HashBytes(msg1048576);
}

[MemoryDiagnoser]
public class Asconxof128Bench
{
	// Messages (these are filled in constructor)
	private byte[] msg64 = new byte[64];
	private byte[] msg1024 = new byte[1024];
	private byte[] msg65536 = new byte[65536];
	private byte[] msg1048576 = new byte[1048576];

	public Asconxof128Bench()
	{
		Random rnd = new Random();
		rnd.NextBytes(msg64);
		rnd.NextBytes(msg1024);
		rnd.NextBytes(msg65536);
		rnd.NextBytes(msg1048576);
	}

	// 64 bytes message
	[Benchmark]
	public byte[] Hash64Bytes() => Asconxof128.HashBytes(msg64, 16);

	// 1024 bytes message
	[Benchmark]
	public byte[] Hash1024Bytes() => Asconxof128.HashBytes(msg1024, 16);

	// 65536 bytes message
	[Benchmark]
	public byte[] Hash65536Bytes() => Asconxof128.HashBytes(msg65536, 16);

	// 1048576 bytes message
	[Benchmark]
	public byte[] Hash1048576Bytes() => Asconxof128.HashBytes(msg1048576, 16);
}

class Program
{
	private static readonly string help = """
	Please select benchmark:
	1. Asconaead128
	2. Asconhash256
	3. Asconxof128

	e.g. dotnet run -c Release 1
	""";
	static void Main(string[] args)
	{
		if (args.Length < 1)
		{
			Console.WriteLine(help);
			return;
		}

		if (args[0] == "1")
		{
			var summary = BenchmarkRunner.Run<Asconaead128Bench>();
		}
		if (args[0] == "2")
		{
			var summary = BenchmarkRunner.Run<Asconhash256Bench>();
		}
		if (args[0] == "3")
		{
			var summary = BenchmarkRunner.Run<Asconxof128Bench>();
		}
	}
}
