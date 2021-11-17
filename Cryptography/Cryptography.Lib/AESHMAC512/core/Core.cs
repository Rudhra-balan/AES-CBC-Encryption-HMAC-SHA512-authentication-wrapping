///////////////////////////////////////////////////////////////////////////////////////////////////
//																			
//  MODULE          :   Core.cs
//  VERSION         :   $VERSION
//  DESCRIPTION     :   Core Encryption And Decryption Functions 
//                      Core encryption function that deals with GZIP compression, AES CBC Encryption and HMAC SHA512 authentication wrapping
//                      Core decryption function that deals with GZIP compression, AES CBC Encryption and HMAC SHA512 authentication wrapping
//                    
//																			
///////////////////////////////////////////////////////////////////////////////////////////////////

using System.Globalization;
using System.Security.Authentication;
using System.Security.Cryptography;

namespace Cryptography.Lib;

public partial class AESHMAC512
{
    //##########################################################
    //#######  Core Encryption And Decryption Functions  #######
    //##########################################################

    /// <summary>
    /// Core encryption function that deals with GZIP compression, AES CBC Encryption and HMAC SHA512 authentication wrapping
    /// </summary>
    /// <param name="data"></param>
    /// <param name="cryptKey"></param>
    /// <param name="authKey"></param>
    /// <returns></returns>
    private byte[] CoreEncrypt(byte[] data, byte[] cryptKey, byte[] authKey)
    {
        //Compresses the supplied data with GZIP before we encrypt it
        data = helpers.GZIPCompress(data);

        //Generates a new IV for this data encryption
        var IV = CreateAESByteIV();

        //Encrypts the data using AES CBC
        data = base.EncryptToBytes(data, cryptKey, IV);

        //Wraps the encrypted AES data in HMAC512 for authentication integrity
        data = EncryptHMACSHA512(data, authKey, IV);

        //Returns the new HMAC SHA512 -> AES CBC encrypted data
        return data;
    }


    /// <summary>
    /// Core decryption function that deals with GZIP compression, AES CBC Encryption and HMAC SHA512 authentication wrapping
    /// </summary>
    /// <param name="data"></param>
    /// <param name="cryptKey"></param>
    /// <param name="authKey"></param>
    /// <param name="maxSecondsDifference"></param>
    /// <returns></returns>
    private byte[] CoreDecrypt(byte[] data, byte[] cryptKey, byte[] authKey, int maxSecondsDifference = 0)
    {
        //Checks the authenticity of the encrypted data supplied, if valid will return the encrypted data and IV
        var calculatedData = DecryptHMACSHA512(data, authKey, maxSecondsDifference);
        //Item1 = IV
        //Item2 = encrypted data

        //Checks Authentication validation went ok and we have the data and IV supplied back
        if (calculatedData != null)
        {
            //Decrypts the data using the key and IV supplied
            data = base.DecryptToType<byte[]>(calculatedData.Item2, cryptKey, calculatedData.Item1);

            //Decompress the supplied data with GZIP after its been decrypted
            data = helpers.GZIPDecompress(data);

            //Returns the unwrapped and decrypted data
            return data;
        }

        return null;
    }


    //#################################################################
    //#######  HMAC SHA512 Encryption And Decryption Functions  #######
    //#################################################################

    /// <summary>
    /// Encrypts a passed encrypted byte array using HMAC SHA512
    /// </summary>
    /// <param name="encryptedData"></param>
    /// <param name="key"></param>
    /// <param name="iv"></param>
    /// <returns></returns>
    private byte[] EncryptHMACSHA512(byte[] encryptedData, byte[] key, byte[] iv)
    {
        using var hmac = new HMACSHA512(key);
        using var encryptionStream = new MemoryStream();
        using (var binaryWriter = new BinaryWriter(encryptionStream))
        {
            //Sets up the current timestamp
            var timestamp = helpers.DateTimeToUnixTimestamp(DateTime.Now);


            //Converts it to a byte array
            var timestampBytes = helpers.ConvertDoubleToByteArray(timestamp);

            helpers.Print("Entrpted time", timestamp.ToString(CultureInfo.InvariantCulture));
            //Prepends a timestamp to the start
            binaryWriter.Write(timestampBytes);

            //Prepends the IV
            binaryWriter.Write(iv);

            //Adds the encrypted data
            binaryWriter.Write(encryptedData);

            //Flushes it to the stream
            binaryWriter.Flush();

            //Calculates the new hash tag for authenticating all data
            var tag = hmac.ComputeHash(encryptionStream.ToArray());

            //Postpends the tag
            binaryWriter.Write(tag);
        }

        //Returns the calculated byte array from the memory stream
        return encryptionStream.ToArray();
    }

    /// <summary>
    /// Decrypts a passed byte array using HMAC SHA512
    /// </summary>
    /// <param name="encryptedData"></param>
    /// <param name="authKey"></param>
    /// <param name="maxSecondsDifference"></param>
    /// <returns></returns>
    private Tuple<byte[], byte[]> DecryptHMACSHA512(byte[] encryptedData, byte[] authKey, int maxSecondsDifference = 0)
    {
        //The HMAC512 data is created in the following order IV -> encrypted data -> authentication tag
        using var hmac = new HMACSHA512(authKey);
        //Calculates the tag length *divides by 8 to go from bits to bytes*
        var tagLength = hmac.HashSize / 8;

        //Calculates the length of the encrypted data
        var dataLength = encryptedData.Length - timestampSize - ivSize - tagLength;

        //Throws an exception if the size is to low
        if (encryptedData.Length < tagLength + timestampSize + ivSize)
            throw new AuthenticationException("The Authentication check does not match the original calculation");

        //Checks the authentication tag validates and matches correctly, if not will throw authentication exception
        //Note: If this does not throw an exception then its been validated
        AuthenticationTagValidation(authKey, encryptedData, tagLength);

        //Checks if an expiration has been set, if so checks if the HMAC is still valid
        if (maxSecondsDifference > 0)
        {
            //Extracts the timestamp from the HMAC data
            var timestampBytes = new byte[timestampSize];
            Array.Copy(encryptedData, 0, timestampBytes, 0, timestampSize);

            //Gets the timestamp
            var timestamp = helpers.ConvertByteArrayToDouble(timestampBytes);

            helpers.Print("Dntrpted time", timestamp.ToString(CultureInfo.InvariantCulture));
            //Converts it to DateTime so we can check
            var dt = helpers.UnixTimeStampToDateTime(timestamp);

            //Adds the additional time allowance check
            dt = dt.AddSeconds(maxSecondsDifference);

            //Gets the current timestamp for right now
            var currentTimestamp = helpers.DateTimeToUnixTimestamp(DateTime.Now);

            //Converts this back into a DateTime object using the Unix timestamp
            var currentDT = helpers.UnixTimeStampToDateTime(currentTimestamp);

            helpers.Print("Decrpted time", dt.ToString("dddd, dd MMMM yyyy HH:mm:ss"));
            //Checks if the time difference is out between the two
            if (dt < currentDT)
                throw new AuthenticationException("The Authentication check failed due to the expiration time.");
        }

        //Extracts the IV from the HMAC data
        var theIV = new byte[ivSize];
        Array.Copy(encryptedData, timestampSize, theIV, 0, ivSize);

        //Extracts the encrypted data fro the HMAC data
        var data = new byte[dataLength];
        Array.Copy(encryptedData, timestampSize + ivSize, data, 0, dataLength);

        //Returns the IV and data as the authentication tag is valid
        return Tuple.Create(theIV, data);
    }

    /// <summary>
    /// Checks the validitiy of the authentication tag for the HMAC SHA512 function
    /// </summary>
    /// <param name="key"></param>
    /// <param name="data"></param>
    /// <param name="tagLength"></param>
    private void AuthenticationTagValidation(byte[] key, byte[] data, int tagLength)
    {
        using var hmac = new HMACSHA512(key);
        //Creates a fresh new tag variable with the calculated length
        var theTag = new byte[tagLength];

        //Copies the supplied authentication tag inside the encrypted data into theTag variable
        Array.Copy(data, data.Length - tagLength, theTag, 0, tagLength);

        //Calculates what the size is for just the IV and data without the authentication tag
        var lengthWithoutTag = data.Length - tagLength;

        //Calculates a new authentication tag using the supplied key, IV and data
        //Note: This is done so we can check if it matches what has been received
        var newTag = hmac.ComputeHash(data, 0, lengthWithoutTag);

        //Checks if the supplied and calculated authentication tags do not match and if so throws an exception
        if (!theTag.SequenceEqual(newTag))
            throw new AuthenticationException("The Authentication check does not match the original calculation");
    }
}