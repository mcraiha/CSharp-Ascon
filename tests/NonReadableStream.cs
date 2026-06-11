
namespace tests;

// Only for testing purposes
public sealed class NonReadableStream : Stream
{
	public override bool CanRead => false;

	public override bool CanSeek => false;

	public override bool CanWrite => false;

	public override long Length => 0;

	public override long Position 
	{ 
		get => 0;
		set
		{
			
		}
	}

	public override void Flush()
	{
		
	}

	public override long Seek(long offset, SeekOrigin origin)
	{
		return 0;
	}

	public override void SetLength(long value)
	{
		
	}

	public override int Read(byte[] buffer, int offset, int count)
	{
		return 0;
	}

	public override void Write(byte[] buffer, int offset, int count)
	{

	}
}