using System;
using System.Numerics;
using System.Buffers.Binary;

namespace CSAscon;

/// <summary>
/// Asconaead128, version 1.3
/// </summary>
public static class Asconaead128
{
	// Defines

	/// <summary>
	/// Version number of Ascon
	/// </summary>
	/// <remarks>Only informational number, not used in library code</remarks>
	public const string CRYPTO_VERSION = "1.3.0";

	/// <summary>
	/// How many bytes key must have
	/// </summary>
	public const int CRYPTO_KEYBYTES = 16;

	/// <summary>
	/// How many bytes nonce must have
	/// </summary>
	public const int CRYPTO_NPUBBYTES = 16;

	/// <summary>
	/// How many bytes tag has
	/// </summary>
	public const int CRYPTO_ABYTES = 16;

	/// <summary>
	/// Initialization vector (IV) 
	/// </summary>
	public const ulong ASCON_128A_IV = 0x00001000808c0001ul;

	/// <summary>
	/// How many bytes are processed at one time (if available)
	/// </summary>
	public const int ASCON_AEAD_RATE = 16;

	/// <summary>
	/// How many values the key has
	/// </summary>
	private const int ASCON_KEYWORDS = (CRYPTO_KEYBYTES + 7) / 8;

	/// <summary>
	/// Variant number
	/// </summary>
	/// <remarks>Only informational number, not used in library code</remarks>
	public const int ASCON_VARIANT = 1;

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

	private static void ascon_loadkey(ref ascon_key_t key, ReadOnlyMemory<byte> k) 
	{
		key.x[0] = LOAD(k, 8);
		key.x[1] = LOAD(k.Slice(8), 8);
	}

	private static void ascon_initaead(ref ascon_state_t s, ascon_key_t key, ReadOnlyMemory<byte> npub) 
	{
		s.x[0] = ASCON_128A_IV;

		s.x[1] = key.x[0];
		s.x[2] = key.x[1];

		s.x[3] = LOAD(npub, 8);
		s.x[4] = LOAD(npub.Slice(8), 8);

		P(s, 12);

		s.x[3] ^= key.x[0];
  		s.x[4] ^= key.x[1];
	}

	private static void ascon_adata(ref ascon_state_t s, ReadOnlyMemory<byte> ad) 
	{
		const int nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;

		if (ad.Length > 0) 
		{
			/* full associated data blocks */
			int adOffset = 0;
			while (ad.Length - adOffset >= ASCON_AEAD_RATE) 
			{
				s.x[0] ^= LOAD(ad.Slice(adOffset), 8);
				s.x[1] ^= LOAD(ad.Slice(adOffset + 8), 8);

				P(s, nr);
				adOffset += ASCON_AEAD_RATE;
			}

			/* final associated data block */
			int pxIndex = 0;
			if (ad.Length - adOffset >= 8) 
			{
				s.x[0] ^= LOAD(ad.Slice(adOffset), 8);
				pxIndex = 1;
				adOffset += 8;
			}

			s.x[pxIndex] ^= PAD(ad.Length - adOffset);
			if (ad.Length - adOffset > 0)
			{
				s.x[pxIndex] ^= LOAD(ad.Slice(adOffset), ad.Length - adOffset);
			}
			P(s, nr);
		}

		/* domain separation */
		s.x[4] ^= DSEP();
	}

	private static void ascon_encrypt(ref ascon_state_t s, Memory<byte> c, ReadOnlyMemory<byte> m) 
	{
		const int nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;
		/* full plaintext blocks */
		int cOffset = 0;
		int mOffset = 0;

		while (m.Length - mOffset >= ASCON_AEAD_RATE) 
		{
			s.x[0] ^= LOAD(m.Slice(mOffset), 8);
			STOREBYTES(c.Slice(cOffset), s.x[0], 8);

			s.x[1] ^= LOAD(m.Slice(mOffset + 8), 8);
	  		STOREBYTES(c.Slice(cOffset + 8), s.x[1], 8);

			P(s, nr);

			mOffset += ASCON_AEAD_RATE;
			cOffset += ASCON_AEAD_RATE;
		}

		/* final associated data block */
		int pxIndex = 0;

		if (m.Length - mOffset >= 8) 
		{
			s.x[0] ^= LOAD(m.Slice(mOffset), 8);
			STOREBYTES(c.Slice(cOffset), s.x[0], 8);
			pxIndex = 1;
			mOffset += 8;
			cOffset += 8;
		}

		s.x[pxIndex] ^= PAD(m.Length - mOffset);
		if (m.Length - mOffset > 0) 
		{
			s.x[pxIndex] ^= LOAD(m.Slice(mOffset), m.Length - mOffset);
			STOREBYTES(c.Slice(cOffset), s.x[pxIndex], m.Length - mOffset);
		}
	}

	private static void ascon_decrypt(ref ascon_state_t s, Memory<byte> m, ReadOnlyMemory<byte> c) 
	{
		const int nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;
		/* full ciphertext blocks */
		int cOffset = 0;
		int mOffset = 0;

		while (c.Length - cOffset >= ASCON_AEAD_RATE) 
		{
			ulong cx = LOAD(c.Slice(cOffset), 8);
			s.x[0] ^= cx;
			STOREBYTES(m.Slice(mOffset), s.x[0], 8);
			s.x[0] = cx;

			cx = LOAD(c.Slice(cOffset + 8), 8);
			s.x[1] ^= cx;
			STOREBYTES(m.Slice(mOffset + 8), s.x[1], 8);
			s.x[1] = cx;
			
			P(s, nr);

			mOffset += ASCON_AEAD_RATE;
			cOffset += ASCON_AEAD_RATE;
		}

		/* final ciphertext block */
		int pxIndex = 0;
		if (c.Length - cOffset >= 8)
		{
			ulong cx = LOAD(c.Slice(cOffset), 8);
			s.x[0] ^= cx;
			STOREBYTES(m.Slice(mOffset), s.x[0], 8);
			s.x[0] = cx;
			pxIndex = 1;
			mOffset += 8;
			cOffset += 8;
		}

		s.x[pxIndex] ^= PAD(c.Length - cOffset);
		if (c.Length - cOffset > 0) 
		{
			ulong cx = LOAD(c.Slice(cOffset), c.Length - cOffset);
			s.x[pxIndex] ^= cx;
			STOREBYTES(m.Slice(mOffset), s.x[pxIndex], c.Length - cOffset);
			s.x[pxIndex] = CLEAR(s.x[pxIndex], c.Length - cOffset);
			s.x[pxIndex] ^= cx;
		}
	}

	private static void ascon_final(ref ascon_state_t s, ascon_key_t key) 
	{
		s.x[2] ^= key.x[0];
		s.x[3] ^= key.x[1];
  
		P(s, 12);

		s.x[3] ^= key.x[0];
		s.x[4] ^= key.x[1];
	}

	private static void P(ascon_state_t s, int nr) 
	{
		if (nr == 12) 
		{
			P12ROUNDS(s);
		}
		if (nr == 8)
		{
			P8ROUNDS(s);
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
		return 0x01ul << (8 * i); 
	}

	private static ulong DSEP()
	{ 
		return 0x80ul << 56; 
	}

	private static ulong CLEAR(ulong w, int n) 
	{
		/* undefined for n == 0 */
		ulong mask = ~0ul << (8 * n);
		return w & mask;
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

	private static void STOREBYTES(Stream output, ulong w, int n) 
	{
		Span<byte> tempArray = stackalloc byte[8];
		BinaryPrimitives.WriteUInt64LittleEndian(tempArray, w);
		if (n == 8)
		{
			output.Write(tempArray);
		}
		else
		{
			output.Write(tempArray.Slice(0, n));
		}
	}

	private static async Task STOREBYTESAsync(Stream output, ulong w, int n) 
	{
		Memory<byte> tempArray = new byte[8];
		BinaryPrimitives.WriteUInt64LittleEndian(tempArray.Span, w);
		if (n == 8)
		{
			await output.WriteAsync(tempArray);
		}
		else
		{
			await output.WriteAsync(tempArray.Slice(0, n));
		}
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
	/// <exception cref="ArgumentException"></exception>
	public static byte[] Encrypt(ReadOnlySpan<byte> message, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
	{
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
	/// Encrypt message stream (add associated data) with given nonce and key
	/// </summary>
	/// <param name="messageInput">Message input stream</param>
	/// <param name="encryptedOutput">Encrypted output stream</param>
	/// <param name="associatedData">Associated data (0 - N bytes)</param>
	/// <param name="nonce">Nonce (16 bytes)</param>
	/// <param name="key">Key (16 bytes)</param>
	/// <exception cref="ArgumentException"></exception>
	public static void Encrypt(Stream messageInput, Stream encryptedOutput, ReadOnlyMemory<byte> associatedData, ReadOnlyMemory<byte> nonce, ReadOnlyMemory<byte> key)
	{
		if (!messageInput.CanRead)
		{
			throw new ArgumentException("Input stream for encrypt operation must be readable!");
		}

		if (!encryptedOutput.CanWrite)
		{
			throw new ArgumentException("Output stream for encrypt operation must be writable!");
		}

		if (nonce.Length != CRYPTO_NPUBBYTES)
		{
			throw new ArgumentException($"Nonce must be {CRYPTO_NPUBBYTES} bytes");
		}

		if (key.Length != CRYPTO_KEYBYTES)
		{
			throw new ArgumentException($"Key must be {CRYPTO_KEYBYTES} bytes");
		}

		ascon_state_t s = new ascon_state_t();

		/* perform ascon computation */
		ascon_key_t asconKey = new ascon_key_t();
		ascon_loadkey(ref asconKey, key);
		ascon_initaead(ref s, asconKey, nonce);
		ascon_adata(ref s, associatedData);

		const int nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;

		/* full plaintext blocks */
		Memory<byte> smallBuffer = new byte[ASCON_AEAD_RATE];
		bool loop = true;
		while (loop)
		{
			int readAmount = messageInput.ReadAtLeast(smallBuffer.Span, ASCON_AEAD_RATE, throwOnEndOfStream: false);
			if (readAmount == ASCON_AEAD_RATE)
			{
				s.x[0] ^= LOAD(smallBuffer, 8);
				STOREBYTES(encryptedOutput, s.x[0], 8);

				s.x[1] ^= LOAD(smallBuffer.Slice(8), 8);
				STOREBYTES(encryptedOutput, s.x[1], 8);

				P(s, nr);
			}
			else
			{
				loop = false;

				/* final associated data block */
				int pxIndex = 0;

				int additionalOffset = 0;

				if (readAmount >= 8) 
				{
					s.x[0] ^= LOAD(smallBuffer, 8);
					STOREBYTES(encryptedOutput, s.x[0], 8);
					pxIndex = 1;
					additionalOffset += 8;
				}

				s.x[pxIndex] ^= PAD(readAmount - additionalOffset);
				if (readAmount - additionalOffset > 0) 
				{
					s.x[pxIndex] ^= LOAD(smallBuffer.Slice(additionalOffset, readAmount - additionalOffset), readAmount - additionalOffset);
					STOREBYTES(encryptedOutput, s.x[pxIndex], readAmount - additionalOffset);
				}
			}
		}

		ascon_final(ref s, asconKey);

		/* set tag */
		STOREBYTES(encryptedOutput, s.x[3], 8);
		STOREBYTES(encryptedOutput, s.x[4], 8);
	}

	/// <summary>
	/// Encrypt message stream (add associated data) with given nonce and key, async
	/// </summary>
	/// <param name="messageInput">Message input stream</param>
	/// <param name="encryptedOutput">Encrypted output stream</param>
	/// <param name="associatedData">Associated data (0 - N bytes)</param>
	/// <param name="nonce">Nonce (16 bytes)</param>
	/// <param name="key">Key (16 bytes)</param>
	/// <exception cref="ArgumentException"></exception>
	public static async Task EncryptAsync(Stream messageInput, Stream encryptedOutput, ReadOnlyMemory<byte> associatedData, ReadOnlyMemory<byte> nonce, ReadOnlyMemory<byte> key)
	{
		if (!messageInput.CanRead)
		{
			throw new ArgumentException("Input stream for encrypt operation must be readable!");
		}

		if (!encryptedOutput.CanWrite)
		{
			throw new ArgumentException("Output stream for encrypt operation must be writable!");
		}

		if (nonce.Length != CRYPTO_NPUBBYTES)
		{
			throw new ArgumentException($"Nonce must be {CRYPTO_NPUBBYTES} bytes");
		}

		if (key.Length != CRYPTO_KEYBYTES)
		{
			throw new ArgumentException($"Key must be {CRYPTO_KEYBYTES} bytes");
		}

		ascon_state_t s = new ascon_state_t();

		/* perform ascon computation */
		ascon_key_t asconKey = new ascon_key_t();
		ascon_loadkey(ref asconKey, key);
		ascon_initaead(ref s, asconKey, nonce);
		ascon_adata(ref s, associatedData);

		const int nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;

		/* full plaintext blocks */
		Memory<byte> smallBuffer = new byte[ASCON_AEAD_RATE];
		bool loop = true;
		while (loop)
		{
			int readAmount = await messageInput.ReadAtLeastAsync(smallBuffer, ASCON_AEAD_RATE, throwOnEndOfStream: false);
			if (readAmount == ASCON_AEAD_RATE)
			{
				s.x[0] ^= LOAD(smallBuffer, 8);
				await STOREBYTESAsync(encryptedOutput, s.x[0], 8);

				s.x[1] ^= LOAD(smallBuffer.Slice(8), 8);
				await STOREBYTESAsync(encryptedOutput, s.x[1], 8);

				P(s, nr);
			}
			else
			{
				loop = false;

				/* final associated data block */
				int pxIndex = 0;

				int additionalOffset = 0;

				if (readAmount >= 8) 
				{
					s.x[0] ^= LOAD(smallBuffer, 8);
					await STOREBYTESAsync(encryptedOutput, s.x[0], 8);
					pxIndex = 1;
					additionalOffset += 8;
				}

				s.x[pxIndex] ^= PAD(readAmount - additionalOffset);
				if (readAmount - additionalOffset > 0) 
				{
					s.x[pxIndex] ^= LOAD(smallBuffer.Slice(additionalOffset, readAmount - additionalOffset), readAmount - additionalOffset);
					await STOREBYTESAsync(encryptedOutput, s.x[pxIndex], readAmount - additionalOffset);
				}
			}
		}

		ascon_final(ref s, asconKey);

		/* set tag */
		await STOREBYTESAsync(encryptedOutput, s.x[3], 8);
		await STOREBYTESAsync(encryptedOutput, s.x[4], 8);
	}

	/// <summary>
	/// Decrypt encoded message and verify tag
	/// </summary>
	/// <param name="encryptedBytes">Encrypted bytes (16 - N bytes)</param>
	/// <param name="associatedData">Associated data (0 - N bytes)</param>
	/// <param name="nonce">Nonce (16 bytes)</param>
	/// <param name="key">Key (16 bytes)</param>
	/// <returns>Decrypted byte array (size is 16 bytes less than encrypted bytes's size)</returns>
	public static byte[] Decrypt(ReadOnlySpan<byte> encryptedBytes, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
	{
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
	/// Decrypt encoded message and verify tag
	/// </summary>
	/// <param name="encryptedInput">Encrypted stream input</param>
	/// <param name="decryptedOutput">Decrypted stream output</param>
	/// <param name="associatedData">Associated data (0 - N bytes)</param>
	/// <param name="nonce">Nonce (16 bytes)</param>
	/// <param name="key">Key (16 bytes)</param>
	/// <returns>0 on success; Otherwise failure</returns>
	/// <exception cref="ArgumentException"></exception>
	public static int Decrypt(Stream encryptedInput, Stream decryptedOutput, ReadOnlyMemory<byte> associatedData, ReadOnlyMemory<byte> nonce, ReadOnlyMemory<byte> key)
	{
		if (!encryptedInput.CanRead)
		{
			throw new ArgumentException("Input stream for decrypt operation must be readable!");
		}

		if (!decryptedOutput.CanWrite)
		{
			throw new ArgumentException("Output stream for decrypt operation must be writable!");
		}

		if (nonce.Length != CRYPTO_NPUBBYTES)
		{
			throw new ArgumentException($"Nonce must be {CRYPTO_NPUBBYTES} bytes");
		}

		if (key.Length != CRYPTO_KEYBYTES)
		{
			throw new ArgumentException($"Key must be {CRYPTO_KEYBYTES} bytes");
		}

		ascon_state_t s = new ascon_state_t();

		/* perform ascon computation */
		ascon_key_t asconKey = new ascon_key_t();
		ascon_loadkey(ref asconKey, key);
		ascon_initaead(ref s, asconKey, nonce);
		ascon_adata(ref s, associatedData);
		
		const int nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;
		/* full ciphertext blocks */
		Memory<byte> primaryBuffer = new byte[ASCON_AEAD_RATE]; // This can be optimized
		Memory<byte> secondaryyBuffer = new byte[ASCON_AEAD_RATE];
		Memory<byte> tagBuffer = new byte[CRYPTO_ABYTES];

		int readAmount = encryptedInput.ReadAtLeast(primaryBuffer.Span, ASCON_AEAD_RATE, throwOnEndOfStream: false);

		if (readAmount < CRYPTO_ABYTES)
		{
			// Not enough bytes for tag
			return -1;
		}

		bool loop = true;
		while (loop)
		{
			readAmount = encryptedInput.ReadAtLeast(secondaryyBuffer.Span, ASCON_AEAD_RATE, throwOnEndOfStream: false);

			if (readAmount == ASCON_AEAD_RATE)
			{
				ulong cx = LOAD(primaryBuffer, 8);
				s.x[0] ^= cx;
				STOREBYTES(decryptedOutput, s.x[0], 8);
				s.x[0] = cx;

				cx = LOAD(primaryBuffer.Slice(8), 8);
				s.x[1] ^= cx;
				STOREBYTES(decryptedOutput, s.x[1], 8);
				s.x[1] = cx;
				
				P(s, nr);

				secondaryyBuffer.CopyTo(primaryBuffer);
			}
			else
			{
				loop = false;

				secondaryyBuffer.Slice(0, readAmount).CopyTo(tagBuffer.Slice(CRYPTO_ABYTES - readAmount));
				primaryBuffer.Slice(readAmount, CRYPTO_ABYTES - readAmount).CopyTo(tagBuffer);

				/* final ciphertext block */
				int pxIndex = 0;

				int additionalOffset = 0;

				if (readAmount >= 8)
				{
					ulong cx = LOAD(primaryBuffer, 8);
					s.x[0] ^= cx;
					STOREBYTES(decryptedOutput, s.x[0], 8);
					s.x[0] = cx;
					pxIndex = 1;
					additionalOffset += 8;
				}

				s.x[pxIndex] ^= PAD(readAmount - additionalOffset);
				if (readAmount - additionalOffset > 0) 
				{
					ulong cx = LOAD(primaryBuffer.Slice(additionalOffset, readAmount - additionalOffset), readAmount - additionalOffset);
					s.x[pxIndex] ^= cx;
					STOREBYTES(decryptedOutput, s.x[pxIndex], readAmount - additionalOffset);
					s.x[pxIndex] = CLEAR(s.x[pxIndex], readAmount - additionalOffset);
					s.x[pxIndex] ^= cx;
				}
			}
		}

		ascon_final(ref s, asconKey);
		/* verify tag (should be constant time, check compiler output) */
		s.x[3] ^= LOAD(tagBuffer, 8);
		s.x[4] ^= LOAD(tagBuffer.Slice(8), 8);
		return NOTZERO(s.x[3], s.x[4]);
	}

	/// <summary>
	/// Decrypt encoded message and verify tag, async
	/// </summary>
	/// <param name="encryptedInput">Encrypted stream input</param>
	/// <param name="decryptedOutput">Decrypted stream output</param>
	/// <param name="associatedData">Associated data (0 - N bytes)</param>
	/// <param name="nonce">Nonce (16 bytes)</param>
	/// <param name="key">Key (16 bytes)</param>
	/// <returns>0 on success; Otherwise failure</returns>
	/// <exception cref="ArgumentException"></exception>
	public static async Task<int> DecryptAsync(Stream encryptedInput, Stream decryptedOutput, ReadOnlyMemory<byte> associatedData, ReadOnlyMemory<byte> nonce, ReadOnlyMemory<byte> key)
	{
		if (!encryptedInput.CanRead)
		{
			throw new ArgumentException("Input stream for decrypt operation must be readable!");
		}

		if (!decryptedOutput.CanWrite)
		{
			throw new ArgumentException("Output stream for decrypt operation must be writable!");
		}

		if (nonce.Length != CRYPTO_NPUBBYTES)
		{
			throw new ArgumentException($"Nonce must be {CRYPTO_NPUBBYTES} bytes");
		}

		if (key.Length != CRYPTO_KEYBYTES)
		{
			throw new ArgumentException($"Key must be {CRYPTO_KEYBYTES} bytes");
		}

		ascon_state_t s = new ascon_state_t();

		/* perform ascon computation */
		ascon_key_t asconKey = new ascon_key_t();
		ascon_loadkey(ref asconKey, key);
		ascon_initaead(ref s, asconKey, nonce);
		ascon_adata(ref s, associatedData);
		
		const int nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;
		/* full ciphertext blocks */
		Memory<byte> primaryBuffer = new byte[ASCON_AEAD_RATE]; // This can be optimized
		Memory<byte> secondaryyBuffer = new byte[ASCON_AEAD_RATE];
		Memory<byte> tagBuffer = new byte[CRYPTO_ABYTES];

		int readAmount = await encryptedInput.ReadAtLeastAsync(primaryBuffer, ASCON_AEAD_RATE, throwOnEndOfStream: false);

		if (readAmount < CRYPTO_ABYTES)
		{
			// Not enough bytes for tag
			return -1;
		}

		bool loop = true;
		while (loop)
		{
			readAmount = await encryptedInput.ReadAtLeastAsync(secondaryyBuffer, ASCON_AEAD_RATE, throwOnEndOfStream: false);

			if (readAmount == ASCON_AEAD_RATE)
			{
				ulong cx = LOAD(primaryBuffer, 8);
				s.x[0] ^= cx;
				await STOREBYTESAsync(decryptedOutput, s.x[0], 8);
				s.x[0] = cx;

				cx = LOAD(primaryBuffer.Slice(8), 8);
				s.x[1] ^= cx;
				await STOREBYTESAsync(decryptedOutput, s.x[1], 8);
				s.x[1] = cx;
				
				P(s, nr);

				secondaryyBuffer.CopyTo(primaryBuffer);
			}
			else
			{
				loop = false;

				secondaryyBuffer.Slice(0, readAmount).CopyTo(tagBuffer.Slice(CRYPTO_ABYTES - readAmount));
				primaryBuffer.Slice(readAmount, CRYPTO_ABYTES - readAmount).CopyTo(tagBuffer);

				/* final ciphertext block */
				int pxIndex = 0;

				int additionalOffset = 0;

				if (readAmount >= 8)
				{
					ulong cx = LOAD(primaryBuffer, 8);
					s.x[0] ^= cx;
					await STOREBYTESAsync(decryptedOutput, s.x[0], 8);
					s.x[0] = cx;
					pxIndex = 1;
					additionalOffset += 8;
				}

				s.x[pxIndex] ^= PAD(readAmount - additionalOffset);
				if (readAmount - additionalOffset > 0) 
				{
					ulong cx = LOAD(primaryBuffer.Slice(additionalOffset, readAmount - additionalOffset), readAmount - additionalOffset);
					s.x[pxIndex] ^= cx;
					await STOREBYTESAsync(decryptedOutput, s.x[pxIndex], readAmount - additionalOffset);
					s.x[pxIndex] = CLEAR(s.x[pxIndex], readAmount - additionalOffset);
					s.x[pxIndex] ^= cx;
				}
			}
		}

		ascon_final(ref s, asconKey);
		/* verify tag (should be constant time, check compiler output) */
		s.x[3] ^= LOAD(tagBuffer, 8);
		s.x[4] ^= LOAD(tagBuffer.Slice(8), 8);
		return NOTZERO(s.x[3], s.x[4]);
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
		ascon_adata(ref s, new ReadOnlyMemory<byte>(ad, 0, adlen));
		ascon_encrypt(ref s, c, new ReadOnlyMemory<byte>(m, 0, mlen));
		ascon_final(ref s, key);
		/* set tag */
		STOREBYTES(new Memory<byte>(c, mlen, 8), s.x[3], 8);
		STOREBYTES(new Memory<byte>(c, mlen + 8, 8), s.x[4], 8);
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
		ascon_adata(ref s, new ReadOnlyMemory<byte>(ad, 0, adlen));
		ascon_decrypt(ref s, m, new ReadOnlyMemory<byte>(c, 0, clen));
		ascon_final(ref s, key);
		/* verify tag (should be constant time, check compiler output) */
		s.x[3] ^= LOAD(new ReadOnlyMemory<byte>(c, clen, 8), 8);
		s.x[4] ^= LOAD(new ReadOnlyMemory<byte>(c, clen + 8, 8), 8);
		return NOTZERO(s.x[3], s.x[4]);
	}
}
