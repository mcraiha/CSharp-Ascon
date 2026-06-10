using NUnit.Framework;
using CSAscon;
using System.IO;

namespace tests;

public class Asconxof128Tests
{
	private static readonly List<(byte[], int, byte[])> expectedAndInput = new List<(byte[], int, byte[])>()
	{
		(new byte[] { 0x47, 0x3d, 0x5e, 0x61, 0x64, 0xf5, 0x8b, 0x39 }, 8, new byte[] { }),
		(new byte[] { 0x47, 0x3d, 0x5e, 0x61, 0x64, 0xf5, 0x8b, 0x39, 0xdf, 0xd8, 0x4a, 0xac, 0xdb, 0x8a, 0xe4, 0x2e }, 16, new byte[] { }),
		(new byte[] { 0x61, 0x2F }, 2, new byte[] { 0x1E }),
		(new byte[] { 0x58, 0xac, 0x19, 0x82, 0xd9, 0x37, 0xe4, 0x77, 0x1c, 0x3d, 0x50, 0x13, 0xef, 0xce, 0xc6, 0xb7 }, 16, "123456789012345678901234567890123456789012345678901234567890"u8.ToArray()),
		//(new byte[] {0x4F, 0x43, 0xB1, 0x13, 0xEF, 0x4F, 0xAD, 0x75, 0x25, 0x4A, 0xF6, 0xFD, 0xB4, 0x35, 0xA5, 0x87, 0x46, 0x2F, 0x98, 0xA4, 0xFC, 0x70, 0xA6, 0x64, 0xFA, 0x35, 0xB7, 0x94, 0x63, 0x6F, 0x94, 0xCE}, new byte[] { 0x8F, 0x54, 0x3F, 0x18, 0x68, 0x3D, 0x3B, 0x2F, 0xD0, 0x72, 0x2B, 0xEC, 0x60, 0x9C, 0xF3, 0x2C }),
	};

	[SetUp]
	public void Setup()
	{

	}

	[Test, Description("Test some simple array inputs with crypto_hash")]
	public void SimpleInputsArray_crypto_hashTest()
	{
		// Arrange

		// Act

		// Assert
		foreach ((byte[] expected, int outputLength, byte[] input) in expectedAndInput)
		{
			byte[] tempBytes = new byte[outputLength];
			int returnValue = Asconxof128.crypto_hash(tempBytes, input);
			Assert.That(returnValue, Is.EqualTo(0));
			Assert.That(tempBytes, Is.EqualTo(expected));
		}
	}

	[Test, Description("Test some simple array inputs with HashBytes")]
	public void SimpleInputsArray_HashBytesTest()
	{
		// Arrange

		// Act

		// Assert
		foreach ((byte[] expected, int outputLength, byte[] input) in expectedAndInput)
		{
			byte[] hash = Asconxof128.HashBytes(input, outputLength);
			Assert.That(hash, Is.EqualTo(expected));
		}
	}

	[Test, Description("Test some simple stream inputs with HashBytes")]
	public void SimpleInputsStreamTest()
	{
		// Arrange

		// Act

		// Assert
		foreach ((byte[] expected, int outputLength, byte[] input) in expectedAndInput)
		{
			byte[] hash = Asconxof128.HashBytes(new MemoryStream(input), outputLength);
			Assert.That(hash, Is.EqualTo(expected), $"Input: {Convert.ToHexString(input)}");
		}
	}

	[Test, Description("Test some simple stream inputs with HashBytesAsync")]
	public async Task SimpleInputsStreamAsyncTest()
	{
		// Arrange

		// Act

		// Assert
		foreach ((byte[] expected, int outputLength, byte[] input) in expectedAndInput)
		{
			byte[] hash = await Asconxof128.HashBytesAsync(new MemoryStream(input), outputLength);
			Assert.That(hash, Is.EqualTo(expected), $"Input: {Convert.ToHexString(input)}");
		}
	}

	[Test, Description("Test out GenKat inputs")]
	public void GenKatTest()
	{
		// Arrange
		List<byte> input = new List<byte>(); // This will be modified in every loop
		int count = 1;
		byte byteToAdd = 0;

		byte[] tempBytes = new byte[64];

		StringWriter sw = new StringWriter();

		string expected = File.ReadAllText("LWC_XOF_KAT_128_512.txt");

		// Act
		for (; count < 1026; count++)
		{
			byte[] inputArray = input.ToArray();

			Asconxof128.crypto_hash(tempBytes, inputArray);
			sw.Write($"Count = {count}\n");
			sw.Write($"Msg = {Convert.ToHexString(inputArray)}\n");
			sw.Write($"MD = {Convert.ToHexString(tempBytes)}\n");
			sw.Write("\n");

			input.Add(byteToAdd);
			byteToAdd++;
		}

		// Assert
		//Console.WriteLine(sw.ToString());
		Assert.That(sw.ToString(), Is.EqualTo(expected));
	}
}