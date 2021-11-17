///////////////////////////////////////////////////////////////////////////////////////////////////
//																			
//  MODULE          :   KeyGenerator.cs
//  VERSION         :   $VERSION
//  DESCRIPTION     :   Hashes a value using secret from configuration
//                    
//                      
//																			
///////////////////////////////////////////////////////////////////////////////////////////////////

using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace Cryptography;

public partial class Helpers
{
    /// <summary>
    /// Hashes a value using secret from configuration
    /// </summary>
    /// <param name="value">Hashed value 32 bytes / 256bit</param>
    /// <returns></returns>
    public string CreateKey(string value)
    {
        var hashed = "";
        var salt = IVHash(value);
        var saltBytes = Encoding.ASCII.GetBytes(salt);

        // validating the Password for Null Exception
        if (!string.IsNullOrEmpty(value))
            // Return a 256 bit hash based on SHA256 and 10000 iterations
            hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                NormalizeNumbers(value),
                saltBytes,
                KeyDerivationPrf.HMACSHA256,
                10000,
                256 / 8)
            );

        return hashed;
    }


    /// <summary>
    /// Represents the method that will be used to Encrypt
    /// the given data.
    /// </summary>
    /// <param name="value">
    /// A <see cref="string"/> that holds the data to be encrypted.
    /// </param>
    /// <returns>
    /// A <see cref="string"/> that holds the Encrypted data.
    /// </returns>
    public string IVHash(string value)
    {
        SymmetricAlgorithm tdesProvider = null;

        try
        {
            byte[] keyArray = null;
            var toEncryptArray =
                Encoding.UTF8.GetBytes(value);

            tdesProvider = CreateDESInstance($"{value}");

            var cTransform = tdesProvider.CreateEncryptor();

            var resultArray = cTransform.TransformFinalBlock
                (toEncryptArray, 0, toEncryptArray.Length);

            return Convert.ToBase64String
                (resultArray, 0, resultArray.Length);
        }
        catch (Exception ex)
        {
            throw ex;
        }
        finally
        {
            if (tdesProvider != null)
                tdesProvider.Clear();
        }
    }


    /// <summary>
    /// Creates a cryptographic service provider that is used for
    /// encrypting and decrypting data.
    /// </summary>
    /// <returns>
    /// A <see cref="System.Security.Cryptography
    /// .TripleDESCryptoServiceProvider"/> that holds the cryptographic
    /// service provider instance.
    /// </returns>
    private SymmetricAlgorithm CreateDESInstance(string encryptionKey)
    {
        var tdesProvider =
            new TripleDESCryptoServiceProvider();

        var keyArray = Encoding.UTF8.GetBytes(encryptionKey);


        tdesProvider.Key = GetByte(keyArray, tdesProvider.Key.Length);

        tdesProvider.Mode = CipherMode.ECB;

        tdesProvider.Padding = PaddingMode.PKCS7;

        return tdesProvider;
    }

    private string NormalizeNumbers(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return text;

        var normalized = new StringBuilder();

        var allNumbers = text.Distinct().ToArray();

        foreach (var ch in allNumbers)
        {
            var equalNumber = 0b0000_1111 & (byte) ch;
            normalized.Append(equalNumber);
        }

        var dateByte = Encoding.ASCII.GetBytes(normalized.ToString());

        var normalizeByte = GetByte(dateByte);

        var base64String = Convert.ToBase64String(normalizeByte);

        return base64String;
    }

    private void SwapByteArray(byte[] a)
    {
        // if array is odd we set limit to a.Length - 1.
        var limit = a.Length - a.Length % 2;
        if (limit < 1) throw new Exception("array too small to be swapped.");
        for (var i = 0; i < limit - 1; i += 2) (a[i], a[i + 1]) = (a[i + 1], a[i]);
    }

    public byte[] GetByte(byte[] bytes, int size = 32)
    {
        var normalizeByte = new byte[size];

        SwapByteArray(bytes);

        var byteIndex = 0;
        for (var index = 0; index < size; index++)
        {
            if (byteIndex == bytes.Length)
            {
                SwapByteArray(bytes);
                byteIndex = 0;
            }

            normalizeByte[index] = bytes[byteIndex];
            byteIndex++;
        }

        return normalizeByte;
    }
}