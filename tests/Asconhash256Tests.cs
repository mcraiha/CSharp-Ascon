using NUnit.Framework;
using CSAscon;
using System.IO;

namespace tests;

public class Asconhash256Tests
{
	[SetUp]
	public void Setup()
	{

	}

	[Test, Description("Test some simple inputs")]
	public void SimpleInputsTest()
	{
		// Arrange
		List<(byte[], byte[])> expectedAndInput = new List<(byte[], byte[])>()
		{
			(new byte[] {0x0B, 0x3B, 0xE5, 0x85, 0x0F, 0x2F, 0x6B, 0x98, 0xCA, 0xF2, 0x9F, 0x8F, 0xDE, 0xA8, 0x9B, 0x64, 0xA1, 0xFA, 0x70, 0xAA, 0x24, 0x9B, 0x8F, 0x83, 0x9B, 0xD5, 0x3B, 0xAA, 0x30, 0x4D, 0x92, 0xB2}, new byte[] {}),
			(new byte[] {0x07, 0x28, 0x62, 0x10, 0x35, 0xAF, 0x3E, 0xD2, 0xBC, 0xA0, 0x3B, 0xF6, 0xFD, 0xE9, 0x00, 0xF9, 0x45, 0x6F, 0x53, 0x30, 0xE4, 0xB5, 0xEE, 0x23, 0xE7, 0xF6, 0xA1, 0xE7, 0x02, 0x91, 0xBC, 0x80}, new byte[] { 0x00}),
		};

		byte[] tempBytes = new byte[32];

		// Act

		// Assert
		foreach ((byte[] expected, byte[] input) in expectedAndInput)
		{
			int returnValue = Asconhash256.crypto_hash(tempBytes, input);
			Assert.That(returnValue, Is.EqualTo(0));
			Assert.That(tempBytes, Is.EqualTo(expected));
		}
	}

	[Test, Description("Test out GenKat inputs")]
	public void GenKatTest()
	{
		// Arrange
		List<byte> input = new List<byte>(); // This will be modified in every loop
		int count = 1;
		byte byteToAdd = 0;

		byte[] tempBytes = new byte[32];

		StringWriter sw = new StringWriter();

		string expected = File.ReadAllText("LWC_HASH_KAT_128_256.txt");

		// Act
		for (; count < 1026; count++)
		{
			byte[] inputArray = input.ToArray();

			Asconhash256.crypto_hash(tempBytes, inputArray);
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