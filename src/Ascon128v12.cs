using System;
using System.Numerics;
using System.Text;
using System.Diagnostics;

namespace CSAscon;

public static class Ascon128v12
{
	// Defines
	public const int CRYPTO_KEYBYTES = 16;
	public const int CRYPTO_NSECBYTES = 0;
	public const int CRYPTO_NPUBBYTES = 16;
	public const int CRYPTO_ABYTES = 16;
	public const int CRYPTO_NOOVERLAP = 1;

	public static bool PRINTSTATE = false;

	[Conditional("DEBUG")]
	private static void print(string name, byte[] var, int len, int offset) 
	{
		Console.Write($"{name}[{len}]=");

		StringBuilder hex = new StringBuilder((int)len * 2);

		for (int i = 0; i < len; ++i) 
		{
			hex.AppendFormat("{0:x2}", var[i+offset]);
		}
		Console.WriteLine(hex.ToString());
	}

	private static ulong ROTR(ulong x, int n) 
	{
		return BitOperations.RotateRight(x, n);
	}

	static void store64(byte[] S, int offset, ulong x) 
	{
		byte[] byteacter = BitConverter.GetBytes(x);

		for (int i = 0; i < 8; ++i)
		{
			S[i + offset] = (byte) byteacter[i];
		}
	}

	static void permutation(byte[] S, int rounds) 
	{
		ulong x0 = 0, x1 = 0, x2 = 0, x3 = 0, x4 = 0;
		ulong t0, t1, t2, t3, t4;

		x0 = BitConverter.ToUInt64(S, 0);
		x1 = BitConverter.ToUInt64(S, 8);
		x2 = BitConverter.ToUInt64(S, 16);
		x3 = BitConverter.ToUInt64(S, 24);
		x4 = BitConverter.ToUInt64(S, 32);

		for (int i = 12-rounds; i < 12; ++i) 
		{
			// addition of round constant
			int diff = (0xf - i);
			x2 ^=  (ulong)((diff << 4) | i);
			// substitution layer
			x0 ^= x4;    x4 ^= x3;    x2 ^= x1;
			t0  = x0;    t1  = x1;    t2  = x2;    t3  = x3;    t4  = x4;
			t0 =~ t0;    t1 =~ t1;    t2 =~ t2;    t3 =~ t3;    t4 =~ t4;
			t0 &= x1;    t1 &= x2;    t2 &= x3;    t3 &= x4;    t4 &= x0;
			x0 ^= t1;    x1 ^= t2;    x2 ^= t3;    x3 ^= t4;    x4 ^= t0;
			x1 ^= x0;    x0 ^= x4;    x3 ^= x2;    x2 =~ x2;
			// linear diffusion layer
			x0 ^= ROTR(x0, 19) ^ ROTR(x0, 28);
			x1 ^= ROTR(x1, 61) ^ ROTR(x1, 39);
			x2 ^= ROTR(x2, 1) ^ ROTR(x2, 6);
			x3 ^= ROTR(x3, 10) ^ ROTR(x3, 17);
			x4 ^= ROTR(x4, 7) ^ ROTR(x4, 41);
		}

		store64(S, 0, x0);
		store64(S, 8, x1);
		store64(S, 16, x2);
		store64(S, 24, x3);
		store64(S, 32, x4);
	}

	public static int crypto_aead_encrypt(byte[] c, int clen, byte[] m, int mlen, byte[] ad, int adlen,
		byte[] nsec, byte[] npub, byte[] k) 
		{

		const int klen = CRYPTO_KEYBYTES;
		const int size = 320 / 8;
		int capacity = 2 * klen;
		int rate = size - capacity;
		const int a = 12;
		int b = 6;
		long s = adlen / rate + 1;
		long t = mlen / rate + 1;
		long l = mlen % rate;

		byte[] S = new byte[size];
		byte[] A = new byte[(int) (s * rate)];
		byte[] M = new byte[(int) (t * rate)];
		int i, j;

		// pad associated data
		for (i = 0; i < adlen; ++i)
		A[i] = ad[i];
		A[adlen] = (byte) 0x80;
		for (i = adlen + 1; i < s * rate; ++i)
		A[i] = 0;
		// pad plaintext
		for (i = 0; i < mlen; ++i)
		M[i] = m[i];
		M[mlen] = (byte) 0x80;
		for (i = mlen + 1; i < t * rate; ++i)
		M[i] = 0;

		// initialization
		S[0] = (byte) (klen * 8);
		S[1] = (byte) (rate * 8);
		S[2] = (byte) a;
		S[3] = (byte) b;
		for (i = 4; i < rate; ++i)
		S[i] = 0;
		for (i = 0; i < klen; ++i)
		S[rate + i] = k[i];
		for (i = 0; i < klen; ++i)
		S[rate + klen + i] = npub[i];

		if (PRINTSTATE) print("initial value:\n", S, size, 0);
		permutation(S, a);
		for (i = 0; i < klen; ++i)
		S[rate + klen + i] ^= k[i];
		if (PRINTSTATE) print("initialization:\n", S, size, 0);

		// process associated data
		if (adlen != 0) {
		for (i = 0; i < s; ++i) {
			for (j = 0; j < rate; ++j)
			S[j] ^= A[i * rate + j];
			permutation(S, b);
		}
		}
		S[size - 1] ^= 1;
		if (PRINTSTATE) print("process associated data:\n", S, size, 0);

		// process plaintext
		for (i = 0; i < t - 1; ++i) {
		for (j = 0; j < rate; ++j) {
			S[j] ^= M[i * rate + j];
			c[i * rate + j] = S[j];
		}
		permutation(S, b);
		}
		for (j = 0; j < rate; ++j)
		S[j] ^= M[(int) ((t - 1) * rate + j)];
		for (j = 0; j < l; ++j)
		c[(int) ((t - 1) * rate + j)] = S[j];
		if (PRINTSTATE) print("process plaintext:\n", S, size, 0);

		// finalization
		for (i = 0; i < klen; ++i)
		S[rate + i] ^= k[i];
		permutation(S, a);
		for (i = 0; i < klen; ++i)
		S[rate + klen + i] ^= k[i];
		if (PRINTSTATE) print("finalization:\n", S, size, 0);

		// return tag
		for (i = 0; i < klen; ++i)
		c[mlen + i] = S[rate + klen + i];
		clen = mlen + klen;

		return clen;
	}

	public static int crypto_aead_decrypt(byte[] m, int mlen, byte[] nsec, byte[] c, int clen, byte[] ad,
		int adlen, byte[] npub, byte[] k) 
	{

		mlen = 0;
		if (clen < CRYPTO_KEYBYTES)
		return -1;

		const int klen = CRYPTO_KEYBYTES;
		const int size = 320 / 8;
		const int capacity = 2 * klen;
		const int rate = size - capacity;
		const int a = 12;
		int b = (klen == 16) ? 6 : 8;
		int s = adlen / rate + 1;
		int t = (clen - klen) / rate + 1;
		int l = (clen - klen) % rate;

		byte[] S = new byte[size];
		byte[] A = new byte[(int) (s * rate)];
		byte[] M = new byte[(int) (t * rate)];
		int i, j;

		// pad associated data
		for (i = 0; i < adlen; ++i)
		A[i] = ad[i];
		A[adlen] = (byte) 0x80;
		for (i = adlen + 1; i < s * rate; ++i)
		A[i] = 0;

		// initialization
		S[0] = (byte) (klen * 8);
		S[1] = (byte) (rate * 8);
		S[2] = (byte) a;
		S[3] = (byte) b;
		for (i = 4; i < rate; ++i)
		S[i] = 0;
		for (i = 0; i < klen; ++i)
		S[rate + i] = k[i];
		for (i = 0; i < klen; ++i)
		S[rate + klen + i] = npub[i];
		permutation(S, a);
		for (i = 0; i < klen; ++i)
		S[rate + klen + i] ^= k[i];

		// process associated data
		if (adlen != 0) {
		for (i = 0; i < s; ++i) {
			for (j = 0; j < rate; ++j)
			S[j] ^= A[i * rate + j];
			permutation(S, b);
		}
		}
		S[size - 1] ^= 1;

		// process plaintext
		for (i = 0; i < t - 1; ++i) {
		for (j = 0; j < rate; ++j) {
			M[i * rate + j] = (byte) (S[j] ^ c[i * rate + j]);
			S[j] = c[i * rate + j];
		}
		permutation(S, b);
		}
		for (j = 0; j < l; ++j)
		M[(int) ((t - 1) * rate + j)] = (byte) (S[j] ^ c[(int) ((t - 1) * rate + j)]);
		for (j = 0; j < l; ++j)
		S[j] = c[(int) ((t - 1) * rate + j)];
		S[l] ^= 0x80;

		// finalization
		for (i = 0; i < klen; ++i)
		S[rate + i] ^= k[i];
		permutation(S, a);
		for (i = 0; i < klen; ++i)
		S[rate + klen + i] ^= k[i];

		// return -1 if verification fails
		for (i = 0; i < klen; ++i)
		if (c[clen - klen + i] != S[rate + klen + i])
			return -1;

		// return plaintext
		mlen = clen - klen;
		for (i = 0; i < mlen; ++i)
		m[i] = M[i];

		return mlen;
	}
}
