using System;
using System.IO;

namespace tests
{
	public static class Common
	{
		public const int KAT_SUCCESS = 0;
		public const int KAT_FILE_OPEN_ERROR = -1;
		public const int KAT_DATA_ERROR = -3;
		public const int KAT_CRYPTO_FAILURE = -4;

		public const int MAX_MESSAGE_LENGTH = 32;
		public const int MAX_ASSOCIATED_DATA_LENGTH = 32;

		public static void WriteToString(StringWriter sw, string label, byte[] data, int length)
		{
			sw.Write(label);
			sw.Write(BitConverter.ToString(data).Replace("-", string.Empty).Substring(0, length * 2));
			sw.Write("\n");
		}

		public static void init_buffer(byte[] buffer, int numbytes) 
		{
			for (int i = 0; i < numbytes; i++) buffer[i] = (byte)i;
		}
	}
}