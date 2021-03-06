///////////////////////////////////////////////////////////////////////////////////////////////////
//																			
//  MODULE          :   Gzip.cs
//  VERSION         :   $VERSION
//  DESCRIPTION     :  GZIP Compression And Decompression Functions
//                    
//																			
///////////////////////////////////////////////////////////////////////////////////////////////////

using System.IO.Compression;

namespace Cryptography;

public partial class Helpers
{
    /// <summary>
    /// Decompresses the supplied byte array from GZIP format
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    public byte[] GZIPDecompress(byte[] data)
    {
        //Opens a memorystream with the input data
        using var inputMS = new MemoryStream(data);
        //Opens the GZIP stream in decompress mode using the input memorystream
        using var zipStream = new GZipStream(inputMS, CompressionMode.Decompress);
        //Opens another memorystream for storing the output
        using var outputMS = new MemoryStream();
        //Processes the bytes through the GZIP decompression and copies them to the output memorystream
        zipStream.CopyTo(outputMS);

        //Returns the decompressed byte[] from the output memorystream
        return outputMS.ToArray();
    }

    /// <summary>
    /// Compresses the supplied byte array in GZIP format
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    public byte[] GZIPCompress(byte[] data)
    {
        //Opens a memorystream
        using var memoryStream = new MemoryStream();
        //Opens the GZIP stream in compression mode using the memorystream
        using (var zipStream = new GZipStream(memoryStream, CompressionMode.Compress))
        {
            //Writes all the bytes of data to the GZIP stream
            zipStream.Write(data, 0, data.Length);
        }

        //Returns the compressed byte array from the memorystream
        return memoryStream.ToArray();
    }
}