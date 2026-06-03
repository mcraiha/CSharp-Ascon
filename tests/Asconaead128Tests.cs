
using NUnit.Framework;
using CSAscon;
using System.IO;

namespace tests;

public class Asconaead128Tests
{
	[SetUp]
	public void Setup()
	{

	}
	
	//[Test, Description("Test out fancy API")]
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
		byte[] encrypted16BytesPlusTag = Asconaead128.Encrypt(messageOf16Bytes, emptyAssociatedData, nonce, key);
		byte[] messageOf16BytesDecrypted = Asconaead128.Decrypt(encrypted16BytesPlusTag, emptyAssociatedData, nonce, key);

		byte[] encryptedManyBytesPlusTag = Asconaead128.Encrypt(messageOfManyBytes, longAssociatedData, nonce, key);
		byte[] messageOfManyBytesDecrypted = Asconaead128.Decrypt(encryptedManyBytesPlusTag, longAssociatedData, nonce, key);

		int func_ret = Asconaead128.crypto_aead_encrypt(messageOf64BytesEncrypted, out int clen, messageOf64Bytes.ToArray(), 63, longAssociatedData.ToArray(), longAssociatedData.Length, null, nonce.ToArray(), key.ToArray());

		// Assert
		Assert.That(messageOf16Bytes.Length, Is.EqualTo(16));
		Assert.IsFalse(messageOfManyBytes.Length % 16 == 0, "Lenght of message of many bytes should NOT be divisable by 16");
		Assert.IsTrue(messageOf64Bytes.Length % 16 == 0, "Lenght of message of 64 bytes should be divisable by 16");

		Assert.That(nonce.Length, Is.EqualTo(16));
		Assert.That(key.Length, Is.EqualTo(16));

		CollectionAssert.AreNotEqual(nonce.ToArray(), key.ToArray());

		Assert.AreEqual(messageOf16Bytes.Length + 16, encrypted16BytesPlusTag.Length);
		CollectionAssert.AreEqual(messageOf16Bytes.ToArray(), messageOf16BytesDecrypted);

		Assert.AreEqual(messageOfManyBytes.Length + 16, encryptedManyBytesPlusTag.Length);
		CollectionAssert.AreEqual(messageOfManyBytes.ToArray(), messageOfManyBytesDecrypted);

		Assert.AreEqual(0, func_ret, $"crypto_aead_encrypt returned {func_ret}");
		Assert.AreEqual(messageOf64BytesEncrypted.Length, clen);
		CollectionAssert.AreEqual(encryptedManyBytesPlusTag, messageOf64BytesEncrypted);
	}

	[Test, Description("Test non power of two message and associated data lengths")]
	public void NonPowerOfTwoLegacyApiTest()
	{
		// Arrange
		byte[] key = new byte[Asconaead128.CRYPTO_KEYBYTES];
		byte[] nonce = new byte[Asconaead128.CRYPTO_NPUBBYTES];

		byte[] msg = new byte[23] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22 };
		byte[] msg2 = new byte[msg.Length];
		byte[] ad = new byte[15] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };
		byte[] ct = new byte[msg.Length + Asconaead128.CRYPTO_ABYTES];

		// Act
		int func_ret = Asconaead128.crypto_aead_encrypt(ct, out int clen, msg, msg.Length, ad, ad.Length, null, nonce, key);
		func_ret = Asconaead128.crypto_aead_decrypt(msg2, out int mlen2, null, ct, clen, ad, ad.Length, nonce, key);

		// Assert
		Assert.That(func_ret, Is.EqualTo(0), $"crypto_aead_decrypt returned {func_ret}");
		Assert.That(ct.Take(msg.Length), Is.Not.EqualTo(msg), "Encrypted message should not contain plaintext message");
		Assert.That(msg2, Is.EqualTo(msg), "Message before encryption should match message after decryption");
	}
	
	[Test, Description("Test out GenKat inputs")]
	public void GenKatTest()
	{
		// Arrange
		byte[] key = new byte[Asconaead128.CRYPTO_KEYBYTES];
		byte[] nonce = new byte[Asconaead128.CRYPTO_NPUBBYTES];
		byte[] msg = new byte[Common.MAX_MESSAGE_LENGTH];
		byte[] msg2 = new byte[Common.MAX_MESSAGE_LENGTH];
		byte[] ad = new byte[Common.MAX_ASSOCIATED_DATA_LENGTH];
		byte[] ct = new byte[Common.MAX_MESSAGE_LENGTH + Asconaead128.CRYPTO_ABYTES];
		int count = 1;
		int func_ret, ret_val = Common.KAT_SUCCESS;

		string expectedKat = File.ReadAllText("LWC_AEAD_KAT_128_128.txt");

		StringWriter sw = new StringWriter();

		Common.init_buffer(key, key.Length, add: 0);
		Common.init_buffer(nonce, nonce.Length, add: 16);
		Common.init_buffer(msg, msg.Length, add: 32);
		Common.init_buffer(ad, ad.Length, add: 48);

		// Act

		// Assert
		for (int mlen = 0; (mlen <= Common.MAX_MESSAGE_LENGTH) && (ret_val == Common.KAT_SUCCESS); mlen++) 
		{
			for (int adlen = 0; adlen <= Common.MAX_ASSOCIATED_DATA_LENGTH; adlen++) 
			{
				sw.Write($"Count = {count}\n");
				count++;
				Common.WriteToString(sw, "Key = ", key, Asconaead128.CRYPTO_KEYBYTES);
				Common.WriteToString(sw, "Nonce = ", nonce, Asconaead128.CRYPTO_NPUBBYTES);
				Common.WriteToString(sw, "PT = ", msg, mlen);
				Common.WriteToString(sw, "AD = ", ad, adlen);

				func_ret = Asconaead128.crypto_aead_encrypt(ct, out int clen, msg, mlen, ad, adlen, null, nonce, key);
				Assert.That(func_ret, Is.EqualTo(0), $"crypto_aead_encrypt returned {func_ret}");

				Common.WriteToString(sw, "CT = ", ct, clen);
				sw.Write("\n");

				func_ret = Asconaead128.crypto_aead_decrypt(msg2, out int mlen2, null, ct, clen, ad, adlen, nonce, key);
				Assert.That(func_ret, Is.EqualTo(0), $"crypto_aead_decrypt returned {func_ret}");

				Assert.That(mlen2, Is.EqualTo(mlen), "$crypto_aead_decrypt returned bad 'mlen': Got <{mlen2}>, expected <{mlen}>");

				Assert.That(msg2.Take(mlen2), Is.EqualTo(msg.Take(mlen)), "crypto_aead_decrypt did not recover the plaintext");

				// test failed verification
				ct[0] ^= 1;
				func_ret = Asconaead128.crypto_aead_decrypt(msg2, out mlen2, null, ct, clen, ad, adlen, nonce, key);

				Assert.That(func_ret, Is.Not.EqualTo(0), "crypto_aead_decrypt should have failed");
			}
		}
		//Console.WriteLine(sw.ToString());
		Assert.That(sw.ToString(), Is.EqualTo(expectedKat));
	}

	[Test, Description("Test out incorrect encryption parameters")]
	public void IncorrectEncryptParametersTest()
	{
		// Arrange
		byte[] messageValid = "0123456789ABCDEFAABBBCC"u8.ToArray();
		byte[] associatedDataValid = "Valid associated data"u8.ToArray();
		byte[] nonceValid = "MY_CAT_IS_NOT_IT"u8.ToArray(); 
		byte[] keyValid = "DO_NOT_USE_IN_PR"u8.ToArray();

		// Act
		var argumentException1 = Assert.Throws<ArgumentException>(() => Asconaead128.Encrypt(new byte[0], associatedDataValid, nonceValid, keyValid) );
		var argumentException2 = Assert.Throws<ArgumentException>(() => Asconaead128.Encrypt(messageValid, associatedDataValid, new byte[0], keyValid) );
		var argumentException3 = Assert.Throws<ArgumentException>(() => Asconaead128.Encrypt(messageValid, associatedDataValid, nonceValid, new byte[0]) );

		// Assert
		Assert.That(argumentException1!.Message, Is.EqualTo("Message should have some bytes"));
		Assert.That(argumentException2!.Message, Is.EqualTo("Nonce must be 16 bytes"));
		Assert.That(argumentException3!.Message, Is.EqualTo("Key must be 16 bytes"));
	}

	[Test, Description("Test out incorrect decryption parameters")]
	public void IncorrectDecryptParametersTest()
	{
		// Arrange
		byte[] encryptedMessageValid = "0123456789ABCDEFAABBBCABABABAC"u8.ToArray();
		byte[] associatedDataValid = "Valid associated data"u8.ToArray();
		byte[] nonceValid = "MY_CAT_IS_NOT_IT"u8.ToArray(); 
		byte[] keyValid = "DO_NOT_USE_IN_PR"u8.ToArray();

		// Act
		var argumentException1 = Assert.Throws<ArgumentException>(() => Asconaead128.Decrypt(new byte[0], associatedDataValid, nonceValid, keyValid) );
		var argumentException2 = Assert.Throws<ArgumentException>(() => Asconaead128.Decrypt(encryptedMessageValid, associatedDataValid, new byte[0], keyValid) );
		var argumentException3 = Assert.Throws<ArgumentException>(() => Asconaead128.Decrypt(encryptedMessageValid, associatedDataValid, nonceValid, new byte[0]) );

		// Assert
		Assert.That(argumentException1!.Message, Is.EqualTo("Encrypted bytes should have at least 16 bytes"));
		Assert.That(argumentException2!.Message, Is.EqualTo("Nonce must be 16 bytes"));
		Assert.That(argumentException3!.Message, Is.EqualTo("Key must be 16 bytes"));
	}
}