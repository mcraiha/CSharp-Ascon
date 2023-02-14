using NUnit.Framework;
using CSAscon;
using System.IO;

namespace tests
{
	public class Ascon128av12Tests
	{
		[SetUp]
		public void Setup()
		{

		}
		
		[Test]
		public void GenKatTest()
		{
			// Arrange
			byte[] key = new byte[Ascon128av12.CRYPTO_KEYBYTES];
  			byte[] nonce = new byte[Ascon128av12.CRYPTO_NPUBBYTES];
  			byte[] msg = new byte[Common.MAX_MESSAGE_LENGTH];
  			byte[] msg2 = new byte[Common.MAX_MESSAGE_LENGTH];
  			byte[] ad = new byte[Common.MAX_ASSOCIATED_DATA_LENGTH];
  			byte[] ct = new byte[Common.MAX_MESSAGE_LENGTH + Ascon128av12.CRYPTO_ABYTES];
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
					Common.WriteToString(sw, "Key = ", key, Ascon128av12.CRYPTO_KEYBYTES);
					Common.WriteToString(sw, "Nonce = ", nonce, Ascon128av12.CRYPTO_NPUBBYTES);
					Common.WriteToString(sw, "PT = ", msg, mlen);
					Common.WriteToString(sw, "AD = ", ad, adlen);

					func_ret = Ascon128av12.crypto_aead_encrypt(ct, out int clen, msg, mlen, ad, adlen, null, nonce, key);
					Assert.AreEqual(0, func_ret, $"crypto_aead_encrypt returned {func_ret}");

					Common.WriteToString(sw, "CT = ", ct, clen);
					sw.Write("\n");

					func_ret = Ascon128av12.crypto_aead_decrypt(msg2, out int mlen2, null, ct, clen, ad, adlen, nonce, key);
					Assert.AreEqual(0, func_ret, $"crypto_aead_decrypt returned {func_ret}");

					Assert.AreEqual(mlen, mlen2, "$crypto_aead_decrypt returned bad 'mlen': Got <{mlen2}>, expected <{mlen}>");

					CollectionAssert.AreEqual(msg.Take(mlen), msg2.Take(mlen2), "crypto_aead_decrypt did not recover the plaintext");

					// test failed verification
					ct[0] ^= 1;
					func_ret = Ascon128av12.crypto_aead_decrypt(msg2, out mlen2, null, ct, clen, ad, adlen, nonce, key);
					//return;
					Assert.AreNotEqual(0, func_ret, "crypto_aead_decrypt should have failed");
				}
			}
			//Console.WriteLine(sw.ToString());
			Assert.AreEqual(sw.ToString(), File.ReadAllText("LWC_AEAD_KAT_128_128_a.txt"));
		}
	}
}