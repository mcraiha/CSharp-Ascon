using System.Numerics;
using System.Buffers.Binary;

namespace CSAscon;

/// <summary>
/// Asconhash256, version 1.3.0
/// </summary>
public static class Asconhash256
{
	/// <summary>
	/// Version number of Ascon
	/// </summary>
	/// <remarks>Only informational number, not used in library code</remarks>
	public const string CRYPTO_VERSION = "1.3.0";
	
	/// <summary>
	/// How many bytes of hash will be produced
	/// </summary>
	public const int CRYPTO_BYTES = 32; // 256 bits

	/// <summary>
	/// How many rounds of the ASCON permutation are applied after each loop
	/// </summary>
	public const int ASCON_HASH_ROUNDS = 12;

	/// <summary>
	/// Variant number
	/// </summary>
	/// <remarks>Only informational number, not used in library code</remarks>
	public const int ASCON_VARIANT = 2;

	/// <summary>
	/// How many bytes are processed per loop if available
	/// </summary>
	public const int ASCON_HASH_RATE = 8;

	private const byte RC0 = 0xf0;
	private const byte RC1 = 0xe1;
	private const byte RC2 = 0xd2;
	private const byte RC3 = 0xc3;
	private const byte RC4 = 0xb4;
	private const byte RC5 = 0xa5;
	private const byte RC6 = 0x96;
	private const byte RC7 = 0x87;
	private const byte RC8 = 0x78;
	private const byte RC9 = 0x69;
	private const byte RCa = 0x5a;
	private const byte RCb = 0x4b;

	/// <summary>
	/// Ascon state, known as S
	/// </summary>
	private struct ascon_state_t
	{
		public ulong[] x = new ulong[5];

		public ascon_state_t()
		{

		}
	}

	private static void ascon_inithash(ref ascon_state_t s)
	{
		/* initialize */
		s.x[0] = 0x9b1e5494e934d681;
		s.x[1] = 0x4bc3a01e333751d2;
		s.x[2] = 0xae65396c6b34b81a;
		s.x[3] = 0x3c7fd4a4d56a4db3;
		s.x[4] = 0x1a5c464906c5976d;
	}

	private static void ascon_absorb(ref ascon_state_t s, ReadOnlyMemory<byte> input, int inlen)
	{
		/* absorb full plaintext blocks */
		int offset = 0;
		while (inlen >= ASCON_HASH_RATE)
		{
			s.x[0] ^= LOAD(input.Slice(offset), 8);
			P(s, ASCON_HASH_ROUNDS);
			offset += ASCON_HASH_RATE;
			inlen -= ASCON_HASH_RATE;
		}

		/* absorb final plaintext block */
		s.x[0] ^= LOAD(input.Slice(offset), inlen);
		s.x[0] ^= PAD(inlen);
	}

	private static void ascon_squeeze(ref ascon_state_t s, Memory<byte> output, int outlen)
	{
		/* squeeze full output blocks */
		P(s, 12);
		int offset = 0;
		while (outlen > ASCON_HASH_RATE)
		{
			STOREBYTES(output.Slice(offset), s.x[0], 8);
			P(s, ASCON_HASH_ROUNDS);
			offset += ASCON_HASH_RATE;
			outlen -= ASCON_HASH_RATE;
		}
		/* squeeze final output block */
		STOREBYTES(output.Slice(offset), s.x[0], outlen);
	}

	private static int ascon_xof(Memory<byte> output, int outlen, ReadOnlyMemory<byte> input, int inlen) 
	{
		ascon_state_t s = new ascon_state_t();

		ascon_inithash(ref s);
		ascon_absorb(ref s, input, inlen);
		ascon_squeeze(ref s, output, outlen);

		return 0;
	}

	/// <summary>
	/// Get Asconhash256 for given input
	/// </summary>
	/// <param name="input">ReadOnlyMemory of input bytes</param>
	/// <returns>Returns byte[] that contains the 32 bytes of hash</returns>
	public static byte[] HashBytes(ReadOnlyMemory<byte> input)
	{
		byte[] returnValue = new byte[CRYPTO_BYTES];

		crypto_hash(returnValue, input);

		return returnValue;
	}

	/// <summary>
	/// Get Asconhash256 for given input
	/// </summary>
	/// <param name="output">Memory output (must be at least 32 bytes!)</param>
	/// <param name="input">ReadOnlyMemory of input bytes</param>
	/// <returns>0 on success</returns>
	/// <remarks>Lowest level, use only if you know what you are doing</remarks>
	public static int crypto_hash(Memory<byte> output, ReadOnlyMemory<byte> input)
	{
		return ascon_xof(output, CRYPTO_BYTES, input, input.Length);
	}

	private static void P(ascon_state_t s, int nr) 
	{
		if (nr == 12)
		{
			P12ROUNDS(s);
		}
	}

	private static void P12ROUNDS(ascon_state_t s) 
	{
		ROUND(s, RC0);
		ROUND(s, RC1);
		ROUND(s, RC2);
		ROUND(s, RC3);
		ROUND(s, RC4);
		ROUND(s, RC5);
		ROUND(s, RC6);
		ROUND(s, RC7);
		ROUND(s, RC8);
		ROUND(s, RC9);
		ROUND(s, RCa);
		ROUND(s, RCb);
	}

	private static void ROUND(ascon_state_t s, byte C) 
	{
		ascon_state_t t = new ascon_state_t();
		/* round constant */
		s.x[2] ^= C;
		/* s-box layer */
		s.x[0] ^= s.x[4];
		s.x[4] ^= s.x[3];
		s.x[2] ^= s.x[1];
		t.x[0] = s.x[0] ^ (~s.x[1] & s.x[2]);
		t.x[2] = s.x[2] ^ (~s.x[3] & s.x[4]);
		t.x[4] = s.x[4] ^ (~s.x[0] & s.x[1]);
		t.x[1] = s.x[1] ^ (~s.x[2] & s.x[3]);
		t.x[3] = s.x[3] ^ (~s.x[4] & s.x[0]);
		t.x[1] ^= t.x[0];
		t.x[3] ^= t.x[2];
		t.x[0] ^= t.x[4];
		/* linear layer */
		s.x[2] = t.x[2] ^ ROR(t.x[2], 6 - 1);
		s.x[3] = t.x[3] ^ ROR(t.x[3], 17 - 10);
		s.x[4] = t.x[4] ^ ROR(t.x[4], 41 - 7);
		s.x[0] = t.x[0] ^ ROR(t.x[0], 28 - 19);
		s.x[1] = t.x[1] ^ ROR(t.x[1], 61 - 39);
		s.x[2] = t.x[2] ^ ROR(s.x[2], 1);
		s.x[3] = t.x[3] ^ ROR(s.x[3], 10);
		s.x[4] = t.x[4] ^ ROR(s.x[4], 7);
		s.x[0] = t.x[0] ^ ROR(s.x[0], 19);
		s.x[1] = t.x[1] ^ ROR(s.x[1], 39);
		s.x[2] = ~s.x[2];
	}

	private static ulong PAD(int i) 
	{ 
		return 0x01ul << (8 * i);
	}

	private static ulong LOAD(ReadOnlyMemory<byte> bytes, int n) 
	{
		if (n < 8)
		{
			Span<byte> tempArray = stackalloc byte[8];
			bytes.Span.CopyTo(tempArray);
			
			return BitConverter.ToUInt64(tempArray);
		}
		else 
		{
			return BitConverter.ToUInt64(bytes.Span);
		}
	}

	private static void STOREBYTES(Memory<byte> bytes, ulong w, int n) 
	{
		Span<byte> tempArray = stackalloc byte[8];
		BinaryPrimitives.WriteUInt64LittleEndian(tempArray, w);
		if (n == 8)
		{
			tempArray.CopyTo(bytes.Span);
		}
		else
		{
			tempArray.Slice(0, n).CopyTo(bytes.Span);
		}
	}

	private static ulong ROR(ulong x, int n) 
	{
		return BitOperations.RotateRight(x, n);
	}
}