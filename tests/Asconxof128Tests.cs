using NUnit.Framework;
using CSAscon;
using System.IO;

namespace tests;

public class Asconxof128Tests
{
	[SetUp]
	public void Setup()
	{

	}

	[Test, Description("Test some simple inputs")]
	public void SimpleInputsTest()
	{
		// Arrange
		List<(byte[], int, byte[])> expectedAndInput = new List<(byte[], int, byte[])>()
		{
			(new byte[] { 0x61, 0x2F }, 2, new byte[] { 0x1E }),
			//(new byte[] {0x07, 0x28, 0x62, 0x10, 0x35, 0xAF, 0x3E, 0xD2, 0xBC, 0xA0, 0x3B, 0xF6, 0xFD, 0xE9, 0x00, 0xF9, 0x45, 0x6F, 0x53, 0x30, 0xE4, 0xB5, 0xEE, 0x23, 0xE7, 0xF6, 0xA1, 0xE7, 0x02, 0x91, 0xBC, 0x80}, new byte[] { 0x00 }),
			//(new byte[] {0x4F, 0x43, 0xB1, 0x13, 0xEF, 0x4F, 0xAD, 0x75, 0x25, 0x4A, 0xF6, 0xFD, 0xB4, 0x35, 0xA5, 0x87, 0x46, 0x2F, 0x98, 0xA4, 0xFC, 0x70, 0xA6, 0x64, 0xFA, 0x35, 0xB7, 0x94, 0x63, 0x6F, 0x94, 0xCE}, new byte[] { 0x8F, 0x54, 0x3F, 0x18, 0x68, 0x3D, 0x3B, 0x2F, 0xD0, 0x72, 0x2B, 0xEC, 0x60, 0x9C, 0xF3, 0x2C }),
		};

		// Act

		// Assert
		foreach ((byte[] expected, int outputLength, byte[] input) in expectedAndInput)
		{
			byte[] tempBytes = new byte[outputLength];
			int returnValue = Asconxof128.crypto_hash(tempBytes, input);
			Assert.That(returnValue, Is.EqualTo(0));
			Assert.That(tempBytes, Is.EqualTo(expected));
		}

		foreach ((byte[] expected, int outputLength, byte[] input) in expectedAndInput)
		{
			byte[] hash = Asconxof128.HashBytes(input, outputLength);
			Assert.That(hash, Is.EqualTo(expected));
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