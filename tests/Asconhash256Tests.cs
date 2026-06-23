using NUnit.Framework;
using CSAscon;
using System.IO;

namespace tests;

public class Asconhash256Tests
{
	private static readonly List<(byte[], byte[])> expectedAndInputSimple = new List<(byte[], byte[])>()
	{
		(new byte[] {0x0B, 0x3B, 0xE5, 0x85, 0x0F, 0x2F, 0x6B, 0x98, 0xCA, 0xF2, 0x9F, 0x8F, 0xDE, 0xA8, 0x9B, 0x64, 0xA1, 0xFA, 0x70, 0xAA, 0x24, 0x9B, 0x8F, 0x83, 0x9B, 0xD5, 0x3B, 0xAA, 0x30, 0x4D, 0x92, 0xB2}, new byte[] {}),
		(new byte[] {0x07, 0x28, 0x62, 0x10, 0x35, 0xAF, 0x3E, 0xD2, 0xBC, 0xA0, 0x3B, 0xF6, 0xFD, 0xE9, 0x00, 0xF9, 0x45, 0x6F, 0x53, 0x30, 0xE4, 0xB5, 0xEE, 0x23, 0xE7, 0xF6, 0xA1, 0xE7, 0x02, 0x91, 0xBC, 0x80}, new byte[] { 0x00 }),
		(new byte[] {0x4f, 0x88, 0xad, 0x8c, 0x65, 0x05, 0x4c, 0xcb, 0x2e, 0x2f, 0x1f, 0x67, 0x06, 0x27, 0x11, 0xb5, 0x9c, 0xa0, 0x57, 0xfd, 0xcb, 0x5d, 0xee, 0x0b, 0xd7, 0xf7, 0x4b, 0x95, 0xc9, 0x3b, 0x33, 0x96}, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }),
		(new byte[] {0xc2, 0x16, 0xf1, 0x9d, 0xd6, 0x15, 0x9c, 0x0b, 0xda, 0xc2, 0x16, 0xd4, 0x69, 0x08, 0xdb, 0x0c, 0x0f, 0x03, 0x13, 0x98, 0xa5, 0x59, 0xbb, 0x79, 0xa8, 0xae, 0x39, 0x59, 0x35, 0x31, 0x33, 0xe5}, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 }),
		(new byte[] {0x4F, 0x43, 0xB1, 0x13, 0xEF, 0x4F, 0xAD, 0x75, 0x25, 0x4A, 0xF6, 0xFD, 0xB4, 0x35, 0xA5, 0x87, 0x46, 0x2F, 0x98, 0xA4, 0xFC, 0x70, 0xA6, 0x64, 0xFA, 0x35, 0xB7, 0x94, 0x63, 0x6F, 0x94, 0xCE}, new byte[] { 0x8F, 0x54, 0x3F, 0x18, 0x68, 0x3D, 0x3B, 0x2F, 0xD0, 0x72, 0x2B, 0xEC, 0x60, 0x9C, 0xF3, 0x2C }),
		(new byte[] {0x6b, 0x7c, 0x97, 0x35, 0x40, 0x1c, 0xed, 0xfb, 0xc4, 0x38, 0x13, 0xe3, 0xcb, 0x3d, 0xe3, 0xca, 0xc9, 0x36, 0x27, 0x59, 0x82, 0xe6, 0x1d, 0xd2, 0x3f, 0xe9, 0x25, 0xbf, 0x7b, 0xf0, 0x44, 0xb7}, "123456789012345678901234567890123456789012345678901234567890"u8.ToArray()),
	};

	private static readonly string expectedKat = File.ReadAllText("LWC_HASH_KAT_128_256.txt");

	[SetUp]
	public void Setup()
	{

	}

	[Test, Description("Test some simple array inputs with crypto_hash")]
	public void SimpleInputsArray_crypto_hashTest()
	{
		// Arrange
		byte[] tempBytes = new byte[32];

		// Act

		// Assert
		foreach ((byte[] expected, byte[] input) in expectedAndInputSimple)
		{
			int returnValue = Asconhash256.crypto_hash(tempBytes, input);
			Assert.That(returnValue, Is.EqualTo(0));
			Assert.That(tempBytes, Is.EqualTo(expected));
		}

		foreach ((byte[] expected, byte[] input) in expectedAndInputSimple)
		{
			byte[] hash = Asconhash256.HashBytes(input);
			Assert.That(hash, Is.EqualTo(expected), $"Input: {Convert.ToHexString(input)}");
		}
	}

	[Test, Description("Test some simple array inputs with HashBytes")]
	public void SimpleInputsArray_HashBytesTest()
	{
		// Arrange

		// Act

		// Assert
		foreach ((byte[] expected, byte[] input) in expectedAndInputSimple)
		{
			byte[] hash = Asconhash256.HashBytes(input);
			Assert.That(hash, Is.EqualTo(expected), $"Input: {Convert.ToHexString(input)}");
		}
	}

	[Test, Description("Test some simple stream inputs with HashBytes")]
	public void SimpleInputsStreamTest()
	{
		// Arrange

		// Act

		// Assert
		foreach ((byte[] expected, byte[] input) in expectedAndInputSimple)
		{
			byte[] hash = Asconhash256.HashBytes(new MemoryStream(input));
			Assert.That(hash, Is.EqualTo(expected), $"Input: {Convert.ToHexString(input)}");
		}
	}

	[Test, Description("Test some simple stream inputs with HashBytesAsync")]
	public async Task SimpleInputsStreamAsyncTest()
	{
		// Arrange

		// Act

		// Assert
		foreach ((byte[] expected, byte[] input) in expectedAndInputSimple)
		{
			byte[] hash = await Asconhash256.HashBytesAsync(new MemoryStream(input));
			Assert.That(hash, Is.EqualTo(expected), $"Input: {Convert.ToHexString(input)}");
		}
	}

	[Test, Description("Test out GenKat inputs with crypto_hash")]
	public void GenKatTestLowLevel()
	{
		// Arrange
		List<byte> input = new List<byte>(capacity: 1026); // This will be modified in every loop
		int count = 1;
		byte byteToAdd = 0;

		byte[] tempBytes = new byte[32];

		StringWriter sw = new StringWriter();

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
		Assert.That(sw.ToString(), Is.EqualTo(expectedKat));
	}

	[Test, Description("Test out GenKat inputs with fancy API using byte arrays")]
	public void GenKatTestFancyByteArrays()
	{
		// Arrange
		List<byte> input = new List<byte>(capacity: 1026); // This will be modified in every loop
		int count = 1;
		byte byteToAdd = 0;

		StringWriter sw = new StringWriter();

		// Act
		for (; count < 1026; count++)
		{
			byte[] inputArray = input.ToArray();

			byte[] tempBytes = Asconhash256.HashBytes(inputArray);
			sw.Write($"Count = {count}\n");
			sw.Write($"Msg = {Convert.ToHexString(inputArray)}\n");
			sw.Write($"MD = {Convert.ToHexString(tempBytes)}\n");
			sw.Write("\n");

			input.Add(byteToAdd);
			byteToAdd++;
		}

		// Assert
		//Console.WriteLine(sw.ToString());
		Assert.That(sw.ToString(), Is.EqualTo(expectedKat));
	}

	[Test, Description("Test out GenKat inputs with fancy API using streams")]
	public void GenKatTestFancyStreams()
	{
		// Arrange
		List<byte> input = new List<byte>(capacity: 1026); // This will be modified in every loop
		int count = 1;
		byte byteToAdd = 0;

		StringWriter sw = new StringWriter();

		// Act
		for (; count < 1026; count++)
		{
			MemoryStream inputStream = new MemoryStream(input.ToArray());
			byte[] tempBytes = Asconhash256.HashBytes(inputStream);
			sw.Write($"Count = {count}\n");
			sw.Write($"Msg = {Convert.ToHexString(inputStream.ToArray())}\n");
			sw.Write($"MD = {Convert.ToHexString(tempBytes)}\n");
			sw.Write("\n");

			input.Add(byteToAdd);
			byteToAdd++;
		}

		// Assert
		//Console.WriteLine(sw.ToString());
		Assert.That(sw.ToString(), Is.EqualTo(expectedKat));
	}

	[Test, Description("Test out GenKat inputs with fancy API using streams async")]
	public async Task GenKatTestFancyStreamsAsync()
	{
		// Arrange
		List<byte> input = new List<byte>(capacity: 1026); // This will be modified in every loop
		int count = 1;
		byte byteToAdd = 0;

		StringWriter sw = new StringWriter();

		// Act
		for (; count < 1026; count++)
		{
			MemoryStream inputStream = new MemoryStream(input.ToArray());
			byte[] tempBytes = await Asconhash256.HashBytesAsync(inputStream);
			sw.Write($"Count = {count}\n");
			sw.Write($"Msg = {Convert.ToHexString(inputStream.ToArray())}\n");
			sw.Write($"MD = {Convert.ToHexString(tempBytes)}\n");
			sw.Write("\n");

			input.Add(byteToAdd);
			byteToAdd++;
		}

		// Assert
		//Console.WriteLine(sw.ToString());
		Assert.That(sw.ToString(), Is.EqualTo(expectedKat));
	}

	[Test, Description("Test out incorrect parameters")]
	public void IncorrectParametersTest()
	{
		// Arrange
		NonReadableStream nonReadableStream = new NonReadableStream();

		// Act
		var argumentException1 = Assert.Throws<ArgumentException>(() => Asconhash256.HashBytes(nonReadableStream) );

		// Assert
		Assert.That(argumentException1!.Message, Is.EqualTo("Stream for hash operation must be readable!"));
	}
}