using System;
using System.Numerics;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace CSAscon;

/// <summary>
/// Ascon128a, version 1.2
/// </summary>
public static class Ascon128av12
{
	// Defines

	/// <summary>
	/// How many bytes key must have
	/// </summary>
	public const int CRYPTO_KEYBYTES = 16;
	private const int CRYPTO_NSECBYTES = 0;

	/// <summary>
	/// How many bytes nonce must have
	/// </summary>
	public const int CRYPTO_NPUBBYTES = 16;

	/// <summary>
	/// How many bytes tag has
	/// </summary>
	public const int CRYPTO_ABYTES = 16;
	private const int CRYPTO_NOOVERLAP = 1;

	/// <summary>
	/// Initialization vector (IV) 
	/// </summary>
	public const ulong ASCON_128A_IV = 0x80800c0800000000ul;

	/// <summary>
	/// How many bytes are processed at one time (if available)
	/// </summary>
	public const int ASCON_AEAD_RATE = 16;

	/// <summary>
	/// How many values the key has
	/// </summary>>
	private const int ASCON_KEYWORDS = (CRYPTO_KEYBYTES + 7) / 8;

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

	/// <summary>
	/// Ascon key
	/// </summary>
	private struct ascon_key_t
	{
		public ulong[] x = new ulong[ASCON_KEYWORDS];

		public ascon_key_t()
		{

		}
	}

	private static void ascon_loadkey(ref ascon_key_t key, byte[] k) 
	{
		key.x[0] = LOAD8(k, 0);
		key.x[1] = LOAD8(k, 8);
	}

	private static void ascon_initaead(ref ascon_state_t s, ascon_key_t key, byte[] npub) 
	{
		s.x[0] = ASCON_128A_IV;

		s.x[1] = key.x[0];
		s.x[2] = key.x[1];

		s.x[3] = LOAD8(npub, 0);
		s.x[4] = LOAD8(npub, 8);
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
				s.x[0] ^= LOAD8(ad, adOffset);
				s.x[1] ^= LOAD8(ad, adOffset + 8);
				printstate("absorb adata", s);
				P(s, nr);
				adOffset += ASCON_AEAD_RATE;
				adlen -= ASCON_AEAD_RATE;
			}

			/* final associated data block */
			int pxIndex = 0;
			if (adlen >= 8) 
			{
				s.x[0] ^= LOAD8(ad, adOffset);
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
			s.x[0] ^= LOAD8(m, mOffset);
			STORE8(c, cOffset, s.x[0]);

			s.x[1] ^= LOAD8(m, mOffset + 8);
	  		STORE8(c, cOffset + 8, s.x[1]);

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
			s.x[0] ^= LOAD8(m, mOffset);
			STORE8(c, cOffset, s.x[0]);
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
			ulong cx = LOAD8(c, cOffset);
			s.x[0] ^= cx;
			STORE8(m, mOffset, s.x[0]);
			s.x[0] = cx;

			cx = LOAD8(c, cOffset + 8);
			s.x[1] ^= cx;
			STORE8(m, mOffset + 8, s.x[1]);
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
			ulong cx = LOAD8(c, cOffset);
			s.x[0] ^= cx;
			STORE8(m, mOffset, s.x[0]);
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

	/// <summary>
	/// Specialized version of LOAD, where we always process 8 bytes at time
	/// </summary>
	/// <param name="bytes">Byte array</param>
	/// <param name="offset">Offset</param>
	private static ulong LOAD8(byte[] bytes, int offset)
	{
		return U64BIG(BitConverter.ToUInt64(bytes, offset));
	}

	private static ulong LOAD(byte[] bytes, int offset, int n) 
	{
		if (n < 8)
		{
			Span<byte> tempArray = stackalloc byte[8];
			for (int i = 0; i < n; i++)
			{
				tempArray[i] = bytes[offset + i];
			}
			
			return U64BIG(BitConverter.ToUInt64(tempArray) & MASK(n));
		}
		else 
		{
			return U64BIG(BitConverter.ToUInt64(bytes, offset) & MASK(n));
		}
	}

	/// <summary>
	/// Specialized version of STORE, where we always process 8 bytes at time
	/// </summary>
	/// <param name="bytes"></param>
	/// <param name="offset"></param>
	/// <param name="w"></param>
	private static void STORE8(byte[] bytes, int offset, ulong w)
	{
		ulong x = 0;
		x |= U64BIG(w);
		byte[] temp = BitConverter.GetBytes(x);
		Buffer.BlockCopy(temp, 0, bytes, offset, 8);
	}

	private static void STORE(byte[] bytes, int offset, ulong w, int n) 
	{
		if (n < 8)
		{
			Span<byte> tempArray = stackalloc byte[8];
			for (int i = 0; i < n; i++)
			{
				tempArray[i] = bytes[offset + i];
			}
			ulong x = BitConverter.ToUInt64(tempArray);
			x &= ~MASK(n);
			x |= U64BIG(w);
			byte[] temp = BitConverter.GetBytes(x);
			Buffer.BlockCopy(temp, 0, bytes, offset, n);
		}
		else
		{
			ulong x = BitConverter.ToUInt64(bytes, offset);
			x &= ~MASK(n);
			x |= U64BIG(w);
			byte[] temp = BitConverter.GetBytes(x);
			Buffer.BlockCopy(temp, 0, bytes, offset, 8);
		}
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

	private static readonly byte[] emptyByteArray = new byte[0];

	/// <summary>
	/// Encrypt message (add associated data) with given nonce and key
	/// </summary>
	/// <param name="message">Message (1 - N bytes)</param>
	/// <param name="associatedData">Associated data (0 - N bytes)</param>
	/// <param name="nonce">Nonce (16 bytes)</param>
	/// <param name="key">Key (16 bytes)</param>
	/// <returns>Encrypted byte array (size is 16 bytes more than message's size)</returns>
	public static byte[] Encrypt(ReadOnlySpan<byte> message, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
	{
		if (message == null)
		{
			throw new NullReferenceException("Message cannot be null");
		}

		if (associatedData == null)
		{
			throw new NullReferenceException("Associated data cannot be null");
		}

		if (nonce == null)
		{
			throw new NullReferenceException("Nonce cannot be null");
		}

		if (key == null)
		{
			throw new NullReferenceException("Key cannot be null");
		}

		if (message.Length < 1)
		{
			throw new ArgumentException("Message should have some bytes");
		}

		if (nonce.Length != CRYPTO_NPUBBYTES)
		{
			throw new ArgumentException($"Nonce must be {CRYPTO_NPUBBYTES} bytes");
		}

		if (key.Length != CRYPTO_KEYBYTES)
		{
			throw new ArgumentException($"Key must be {CRYPTO_KEYBYTES} bytes");
		}

		byte[] encryptedBytes = new byte[message.Length + CRYPTO_ABYTES];

		crypto_aead_encrypt(encryptedBytes, out _, message.ToArray(), message.Length, associatedData.ToArray(), associatedData.Length, emptyByteArray, nonce.ToArray(), key.ToArray());

		return encryptedBytes;
	}

	/// <summary>
	/// Decrypt encoded message
	/// </summary>
	/// <param name="encryptedBytes">Encrypted bytes (16 - N bytes)</param>
	/// <param name="associatedData">Associated data (0 - N bytes)</param>
	/// <param name="nonce">Nonce (16 bytes)</param>
	/// <param name="key">Key (16 bytes)</param>
	/// <returns>Decrypted byte array (size is 16 bytes less than encrypted bytes's size)</returns>
	public static byte[] Decrypt(ReadOnlySpan<byte> encryptedBytes, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
	{
		if (encryptedBytes == null)
		{
			throw new NullReferenceException("Encrypted bytes cannot be null");
		}

		if (associatedData == null)
		{
			throw new NullReferenceException("Associated data cannot be null");
		}

		if (nonce == null)
		{
			throw new NullReferenceException("Nonce cannot be null");
		}

		if (key == null)
		{
			throw new NullReferenceException("Key cannot be null");
		}

		if (encryptedBytes.Length < CRYPTO_ABYTES)
		{
			throw new ArgumentException($"Encrypted bytes should have at least {CRYPTO_ABYTES} bytes");
		}

		if (nonce.Length != CRYPTO_NPUBBYTES)
		{
			throw new ArgumentException($"Nonce must be {CRYPTO_NPUBBYTES} bytes");
		}

		if (key.Length != CRYPTO_KEYBYTES)
		{
			throw new ArgumentException($"Key must be {CRYPTO_KEYBYTES} bytes");
		}

		byte[] decryptedBytes = new byte[encryptedBytes.Length - CRYPTO_ABYTES];

		int result = crypto_aead_decrypt(decryptedBytes, out _, emptyByteArray, encryptedBytes.ToArray(), encryptedBytes.Length, associatedData.ToArray(), associatedData.Length, nonce.ToArray(), key.ToArray());

		if (result != 0)
		{
			throw new Exception("Tag verification failed, either parameters are incorrect or data has been corrupted");
		}

		return decryptedBytes;
	}

	/// <summary>
	/// Encrypt (lowest level method, imitates similar C based call)
	/// </summary>
	/// <param name="c">Encrypted byte array (the result you get, includes tag)</param>
	/// <param name="clen">How many bytes are written to the encrypted array</param>
	/// <param name="m">Message bytes to encrypt</param>
	/// <param name="mlen">How many bytes will be encrypted from message bytes</param>
	/// <param name="ad">Associated data bytes (see https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD) )</param>
	/// <param name="adlen">How many bytes will be uses from Associated data bytes</param>
	/// <param name="nsec">NOT USED (only for API compatibility)</param>
	/// <param name="npub">Nonce as bytes (must be 16 bytes / 128 bits)</param>
	/// <param name="k">Key as bytes (must be 16 bytes / 128 bits)</param>
	/// <returns>0 if everything went correctly with encryption</returns>
	public static int crypto_aead_encrypt(byte[] c, out int clen, byte[] m, int mlen, byte[] ad, int adlen, byte[]? nsec, byte[] npub, byte[] k) 
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

	/// <summary>
	/// Decrypt (lowest level method, imitates similar C based call)
	/// </summary>
	/// <param name="m">Message bytes after decryption</param>
	/// <param name="mlen">How many bytes were decrypted</param>
	/// <param name="nsec">NOT USED (only for API compatibility)</param>
	/// <param name="c">Encrypted byte array (one you want to decrypt)</param>
	/// <param name="clen">How many bytes from encrypted array should be procesessed</param>
	/// <param name="ad">Associated data bytes (see https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD) )</param>
	/// <param name="adlen">How many bytes will be uses from Associated data bytes</param>
	/// <param name="npub">Nonce as bytes (must be 16 bytes / 128 bits)</param>
	/// <param name="k">Key as bytes (must be 16 bytes / 128 bits)</param>
	/// <returns>0 if everything went correctly with decryption</returns>
	public static int crypto_aead_decrypt(byte[] m, out int mlen, byte[]? nsec, byte[] c, int clen, byte[] ad, int adlen, byte[] npub, byte[] k) 
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
