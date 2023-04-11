using NUnit.Framework;
using CSAscon;
using System.IO;

namespace tests
{
	public class Ascon128v12Tests
	{
		[SetUp]
		public void Setup()
		{

		}

		
		[Test]
		public void FancyApiTest()
		{
			// Arrange
			ReadOnlySpan<byte> messageOf16Bytes = "0123456789ABCDEF"u8;
			ReadOnlySpan<byte> messageOfManyBytes = "This is a very long and boring text for testing purposes 😀 !"u8;

			ReadOnlySpan<byte> emptyAssociatedData = new byte[0];
			ReadOnlySpan<byte> longAssociatedData = "YET another crazy user id which is dragon"u8;

			ReadOnlySpan<byte> nonce = "MY_CAT_IS_NOT_IT"u8;
			ReadOnlySpan<byte> key = "DO_NOT_USE_IN_PR"u8;

			Span<byte> messageOf64Bytes = new byte[64];
			messageOfManyBytes.CopyTo(messageOf64Bytes); // Create copy that is divisable by 8
			byte[] messageOf64BytesEncrypted = new byte[79];

			// Act
			byte[] encrypted16BytesPlusTag = Ascon128v12.Encrypt(messageOf16Bytes, emptyAssociatedData, nonce, key);
			byte[] messageOf16BytesDecrypted = Ascon128v12.Decrypt(encrypted16BytesPlusTag, emptyAssociatedData, nonce, key);

			byte[] encryptedManyBytesPlusTag = Ascon128v12.Encrypt(messageOfManyBytes, longAssociatedData, nonce, key);
			byte[] messageOfManyBytesDecrypted = Ascon128v12.Decrypt(encryptedManyBytesPlusTag, longAssociatedData, nonce, key);

			int func_ret = Ascon128v12.crypto_aead_encrypt(messageOf64BytesEncrypted, out int clen, messageOf64Bytes.ToArray(), 63, longAssociatedData.ToArray(), longAssociatedData.Length, null, nonce.ToArray(), key.ToArray());

			// Assert
			Assert.AreEqual(16, messageOf16Bytes.Length);
			Assert.IsFalse(messageOfManyBytes.Length % 16 == 0, "Lenght of message of many bytes should NOT be divisable by 16");
			Assert.IsTrue(messageOf64Bytes.Length % 16 == 0, "Lenght of message of 64 bytes should be divisable by 16");

			Assert.AreEqual(16, nonce.Length);
			Assert.AreEqual(16, key.Length);

			CollectionAssert.AreNotEqual(nonce.ToArray(), key.ToArray());

			Assert.AreEqual(messageOf16Bytes.Length + 16, encrypted16BytesPlusTag.Length);
			CollectionAssert.AreEqual(messageOf16Bytes.ToArray(), messageOf16BytesDecrypted);

			Assert.AreEqual(messageOfManyBytes.Length + 16, encryptedManyBytesPlusTag.Length);
			CollectionAssert.AreEqual(messageOfManyBytes.ToArray(), messageOfManyBytesDecrypted);

			Assert.AreEqual(0, func_ret, $"crypto_aead_encrypt returned {func_ret}");
			Assert.AreEqual(messageOf64BytesEncrypted.Length, clen);
			CollectionAssert.AreEqual(encryptedManyBytesPlusTag, messageOf64BytesEncrypted);
		}
		
		[Test]
		public void GenKatTest()
		{
			// Arrange
			byte[] key = new byte[Ascon128v12.CRYPTO_KEYBYTES];
  			byte[] nonce = new byte[Ascon128v12.CRYPTO_NPUBBYTES];
  			byte[] msg = new byte[Common.MAX_MESSAGE_LENGTH];
  			byte[] msg2 = new byte[Common.MAX_MESSAGE_LENGTH];
  			byte[] ad = new byte[Common.MAX_ASSOCIATED_DATA_LENGTH];
  			byte[] ct = new byte[Common.MAX_MESSAGE_LENGTH + Ascon128v12.CRYPTO_ABYTES];
			int count = 1;
			int func_ret, ret_val = Common.KAT_SUCCESS;

			StringWriter sw = new StringWriter();

			Common.init_buffer(key, key.Length);
			Common.init_buffer(nonce, nonce.Length);
			Common.init_buffer(msg, msg.Length);
			Common.init_buffer(ad, ad.Length);

			// Act

			// Assert
			for (int mlen = 0; (mlen <= Common.MAX_MESSAGE_LENGTH) && (ret_val == Common.KAT_SUCCESS); mlen++) 
			{
				for (int adlen = 0; adlen <= Common.MAX_ASSOCIATED_DATA_LENGTH; adlen++) 
				{
					sw.Write($"Count = {count}\n");
					count++;
					Common.WriteToString(sw, "Key = ", key, Ascon128v12.CRYPTO_KEYBYTES);
					Common.WriteToString(sw, "Nonce = ", nonce, Ascon128v12.CRYPTO_NPUBBYTES);
					Common.WriteToString(sw, "PT = ", msg, mlen);
					Common.WriteToString(sw, "AD = ", ad, adlen);

					func_ret = Ascon128v12.crypto_aead_encrypt(ct, out int clen, msg, mlen, ad, adlen, null, nonce, key);
					Assert.AreEqual(0, func_ret, $"crypto_aead_encrypt returned {func_ret}");

					Common.WriteToString(sw, "CT = ", ct, clen);
					sw.Write("\n");

					func_ret = Ascon128v12.crypto_aead_decrypt(msg2, out int mlen2, null, ct, clen, ad, adlen, nonce, key);
					Assert.AreEqual(0, func_ret, $"crypto_aead_decrypt returned {func_ret}");

					Assert.AreEqual(mlen, mlen2, "$crypto_aead_decrypt returned bad 'mlen': Got <{mlen2}>, expected <{mlen}>");

					CollectionAssert.AreEqual(msg.Take(mlen), msg2.Take(mlen2), "crypto_aead_decrypt did not recover the plaintext");

					// test failed verification
					ct[0] ^= 1;
					func_ret = Ascon128v12.crypto_aead_decrypt(msg2, out mlen2, null, ct, clen, ad, adlen, nonce, key);
					//return;
					Assert.AreNotEqual(0, func_ret, "crypto_aead_decrypt should have failed");
				}
			}
			//Console.WriteLine(sw.ToString());
			Assert.AreEqual(sw.ToString(), File.ReadAllText("LWC_AEAD_KAT_128_128.txt"));
		}
	}
}