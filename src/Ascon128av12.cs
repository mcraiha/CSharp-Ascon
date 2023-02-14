using System;
using System.Numerics;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace CSAscon;

public static class Ascon128av12
{
	// Defines
	public const int CRYPTO_KEYBYTES = 16;
	public const int CRYPTO_NSECBYTES = 0;
	public const int CRYPTO_NPUBBYTES = 16;
	public const int CRYPTO_ABYTES = 16;
	public const int CRYPTO_NOOVERLAP = 1;

	public const ulong ASCON_128A_IV = 0x80800c0800000000ul;

	public const int ASCON_AEAD_RATE = 16;

	public const int ASCON_KEYWORDS = (CRYPTO_KEYBYTES + 7) / 8;

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

	public struct ascon_state_t
	{
		public ulong[] x = new ulong[5];

		public ascon_state_t()
		{

		}
	}

	public struct ascon_key_t
	{
		public ulong[] x = new ulong[ASCON_KEYWORDS];

		public ascon_key_t()
		{

		}
	}

	private static void ascon_loadkey(ref ascon_key_t key, byte[] k) 
	{
		key.x[0] = LOAD(k, 0, 8);
		key.x[1] = LOAD(k, 8, 8);
	}

	private static void ascon_initaead(ref ascon_state_t s, ascon_key_t key, byte[] npub) 
	{
		s.x[0] = ASCON_128A_IV;

		s.x[1] = key.x[0];
		s.x[2] = key.x[1];

		s.x[3] = LOAD(npub, 0, 8);
		s.x[4] = LOAD(npub, 8, 8);
		printstate("init 1st key xor", s);
		P(s, 12);

		s.x[3] ^= key.x[0];
  		s.x[4] ^= key.x[1];

		printstate("init 2nd key xor", s);
	}

	private static void ascon_adata(ref ascon_state_t s, byte[] ad, int adlen) 
	{
		const int nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;

		if (adlen > 0) 
		{
			/* full associated data blocks */
			int adOffset = 0;
			while (adlen >= ASCON_AEAD_RATE) 
			{
				s.x[0] ^= LOAD(ad, adOffset, 8);
				s.x[1] ^= LOAD(ad, adOffset + 8, 8);
				printstate("absorb adata", s);
				P(s, nr);
				adOffset += ASCON_AEAD_RATE;
				adlen -= ASCON_AEAD_RATE;
			}

			/* final associated data block */
			int pxIndex = 0;
			if (adlen >= 8) 
			{
				s.x[0] ^= LOAD(ad, adOffset, 8);
				pxIndex = 1;
				adOffset += 8;
				adlen -= 8;
			}

			s.x[pxIndex] ^= PAD(adlen);
			if (adlen > 0) s.x[pxIndex] ^= LOAD(ad, adOffset, adlen);
			printstate("pad adata", s);
			P(s, nr);
		}

		/* domain separation */
		s.x[4] ^= 1;
		printstate("domain separation", s);
	}

	private static void ascon_encrypt(ref ascon_state_t s, byte[] c, byte[] m, int mlen) 
	{
		const int nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;
		/* full plaintext blocks */
		int cOffset = 0;
		int mOffset = 0;

		while (mlen >= ASCON_AEAD_RATE) 
		{
			s.x[0] ^= LOAD(m, mOffset, 8);
			STORE(c, cOffset, s.x[0], 8);

			s.x[1] ^= LOAD(m, mOffset + 8, 8);
	  		STORE(c, cOffset + 8, s.x[1], 8);

			printstate("absorb plaintext", s);
			P(s, nr);

			mOffset += ASCON_AEAD_RATE;
			cOffset += ASCON_AEAD_RATE;
			mlen -= ASCON_AEAD_RATE;
		}

		/* final associated data block */
		int pxIndex = 0;

		if (mlen >= 8) 
		{
			s.x[0] ^= LOAD(m, mOffset, 8);
			STORE(c, cOffset, s.x[0], 8);
			pxIndex = 1;
			mOffset += 8;
			cOffset += 8;
			mlen -= 8;
		}

		s.x[pxIndex] ^= PAD(mlen);
		if (mlen > 0) 
		{
			s.x[pxIndex] ^= LOAD(m, mOffset, mlen);
			STORE(c, cOffset, s.x[pxIndex], mlen);
		}

		printstate("pad plaintext", s);
	}

	private static void ascon_decrypt(ref ascon_state_t s, byte[] m, byte[] c, int clen) 
	{
		const int nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;
		/* full ciphertext blocks */
		int cOffset = 0;
		int mOffset = 0;

		while (clen >= ASCON_AEAD_RATE) 
		{
			ulong cx = LOAD(c, cOffset, 8);
			s.x[0] ^= cx;
			STORE(m, mOffset, s.x[0], 8);
			s.x[0] = cx;

			cx = LOAD(c, cOffset + 8, 8);
			s.x[1] ^= cx;
			STORE(m, mOffset + 8, s.x[1], 8);
			s.x[1] = cx;
			
			printstate("insert ciphertext", s);
			P(s, nr);

			mOffset += ASCON_AEAD_RATE;
			cOffset += ASCON_AEAD_RATE;
			clen -= ASCON_AEAD_RATE;
		}

		/* final ciphertext block */
		int pxIndex = 0;
		if (clen >= 8)
		{
			ulong cx = LOAD(c, cOffset, 8);
			s.x[0] ^= cx;
			STORE(m, mOffset, s.x[0], 8);
			s.x[0] = cx;
			pxIndex = 1;
			mOffset += 8;
			cOffset += 8;
			clen -= 8;
		}

		s.x[pxIndex] ^= PAD(clen);
		if (clen > 0) 
		{
			ulong cx = LOAD(c, cOffset, clen);
			s.x[pxIndex] ^= cx;
			STORE(m, mOffset, s.x[pxIndex], clen);
			s.x[pxIndex] = CLEAR(s.x[pxIndex], clen);
			s.x[pxIndex] ^= cx;
		}
		printstate("pad ciphertext", s);
	}

	private static void ascon_final(ref ascon_state_t s, ascon_key_t key) 
	{
		s.x[2] ^= key.x[0];
		s.x[3] ^= key.x[1];
  
		printstate("final 1st key xor", s);
		P(s, 12);

		s.x[3] ^= key.x[0];
		s.x[4] ^= key.x[1];

		printstate("final 2nd key xor", s);
	}

	private static void P(ascon_state_t s, int nr) 
	{
		if (nr == 12) P12ROUNDS(s);
		if (nr == 8) P8ROUNDS(s);
		if (nr == 6) P6ROUNDS(s);
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

	private static void P8ROUNDS(ascon_state_t s) 
	{
		ROUND(s, RC4);
		ROUND(s, RC5);
		ROUND(s, RC6);
		ROUND(s, RC7);
		ROUND(s, RC8);
		ROUND(s, RC9);
		ROUND(s, RCa);
		ROUND(s, RCb);
	}

	private static void P6ROUNDS(ascon_state_t s) 
	{
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
		printstate(" round output", s);
	}

	private static int NOTZERO(ulong a, ulong b) 
	{
		ulong result = a | b;
		result |= result >> 32;
		result |= result >> 16;
		result |= result >> 8;
		return ((((int)(result & 0xff) - 1) >> 8) & 1) - 1;
	}

	private static ulong PAD(int i) 
	{ 
		return 0x80ul << (56 - 8 * i); 
	}

	private static ulong CLEAR(ulong w, int n) 
	{
		/* undefined for n == 0 */
		ulong mask = ~0ul >> (8 * n);
		return w & mask;
	}

	private static ulong MASK(int n) 
	{
		/* undefined for n == 0 */
		return ~0ul >> (64 - 8 * n);
	}

	private static ulong LOAD(byte[] bytes, int offset, int n) 
	{
		ulong x = BitConverter.ToUInt64(bytes, offset) & MASK(n);
		return U64BIG(x);
	}

	private static void STORE(byte[] bytes, int offset, ulong w, int n) 
	{
		ulong x = BitConverter.ToUInt64(bytes, offset);
		x &= ~MASK(n);
		x |= U64BIG(w);
		byte[] temp = BitConverter.GetBytes(x);
		Buffer.BlockCopy(temp, 0, bytes, offset, 8);
	}

	private static ulong LOADBYTES(byte[] bytes, int offset, int n) 
	{
		return U64BIG(BitConverter.ToUInt64(bytes, offset));
	}

	private static void STOREBYTES(byte[] bytes, int offset, ulong w, int n) 
	{
		ulong x = U64BIG(w);
		byte[] temp = BitConverter.GetBytes(x);
		Buffer.BlockCopy(temp, 0, bytes, offset, n);
	}

	private static ulong U64BIG(ulong x)
	{
		x = (x >> 32) | (x << 32);
		x = ((x & 0xFFFF0000FFFF0000U) >> 16) | ((x & 0x0000FFFF0000FFFFU) << 16);
		x = ((x & 0xFF00FF00FF00FF00U) >> 8) | ((x & 0x00FF00FF00FF00FFU) << 8);
		return x;
	}

	[Conditional("ASCON_PRINT_STATE")]
	private static void printword(string text, ulong x) 
	{
		Console.Write($"{text}={x:x}");
	}

	[Conditional("ASCON_PRINT_STATE")]
	private static void printstate(string text, ascon_state_t s) 
	{
		Console.Write($"{text}:");
		for (int i = text.Length; i < 17; ++i) Console.Write(" ");
		printword(" x0", s.x[0]);
		printword(" x1", s.x[1]);
		printword(" x2", s.x[2]);
		printword(" x3", s.x[3]);
		printword(" x4", s.x[4]);
		Console.WriteLine();
	}

	private static ulong ROR(ulong x, int n) 
	{
		return BitOperations.RotateRight(x, n);
	}

	public static int crypto_aead_encrypt(byte[] c, out int clen, byte[] m, int mlen, byte[] ad, int adlen, byte[] nsec, byte[] npub, byte[] k) 
	{
		ascon_state_t s = new ascon_state_t();
		clen = mlen + CRYPTO_ABYTES;
		/* perform ascon computation */
		ascon_key_t key = new ascon_key_t();
		ascon_loadkey(ref key, k);
		ascon_initaead(ref s, key, npub);
		ascon_adata(ref s, ad, adlen);
		ascon_encrypt(ref s, c, m, mlen);
		ascon_final(ref s, key);
		/* set tag */
		STOREBYTES(c, mlen, s.x[3], 8);
		STOREBYTES(c, mlen + 8, s.x[4], 8);
		return 0;
	}

	public static int crypto_aead_decrypt(byte[] m, out int mlen, byte[] nsec, byte[] c, int clen, byte[] ad, int adlen, byte[] npub, byte[] k) 
	{
		ascon_state_t s = new ascon_state_t();
		if (clen < CRYPTO_ABYTES)
		{
			mlen = -1;
			return -1;
		}
		mlen = clen = clen - CRYPTO_ABYTES;
		/* perform ascon computation */
		ascon_key_t key = new ascon_key_t();
		ascon_loadkey(ref key, k);
		ascon_initaead(ref s, key, npub);
		ascon_adata(ref s, ad, adlen);
		ascon_decrypt(ref s, m, c, clen);
		ascon_final(ref s, key);
		/* verify tag (should be constant time, check compiler output) */
		s.x[3] ^= LOADBYTES(c, clen, 8);
		s.x[4] ^= LOADBYTES(c, clen + 8, 8);
		return NOTZERO(s.x[3], s.x[4]);
	}
}
