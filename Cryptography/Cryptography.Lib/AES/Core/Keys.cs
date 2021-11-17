//////////////////////////////////////////////////////////////////////////////////////////////////
//																			
//  MODULE          :   Key.cs
//  VERSION         :   $VERSION
//  DESCRIPTION     :   Key and IV Generating Functions 
//																			
//																			
///////////////////////////////////////////////////////////////////////////////////////////////////																		

using System.Security.Cryptography;
using System.Text;

namespace Cryptography.Lib;

public partial class AES
{
    /// <summary>
    /// Generates an IV and returns it in base64 string format
    /// </summary>
    /// <returns></returns>
    public string CreateAESStringIV()
    {
        using (var aes = new AesCryptoServiceProvider())
        {
            aes.KeySize = theKeySize;
            aes.Mode = cipherMode;
            aes.GenerateIV();
            return Convert.ToBase64String(aes.IV);
        }
    }

    /// <summary>
    /// Generates an IV and returns it in a byte array format
    /// </summary>
    /// <returns></returns>
    public byte[] CreateAESByteIV()
    {
        using var aes = new AesCryptoServiceProvider();
        aes.KeySize = theKeySize;
        aes.Mode = cipherMode;
        aes.GenerateIV();
        return aes.IV;
    }

    /// <summary>
    /// Generates a 256 key and returns it in base64 string format
    /// </summary>
    /// <returns></returns>
    public string CreateAESStringKey()
    {
        using var aes = new AesCryptoServiceProvider();
        aes.KeySize = theKeySize;
        aes.Mode = cipherMode;
        aes.GenerateKey();
        return Convert.ToBase64String(aes.Key);
    }

    /// <summary>
    /// Generates a 256 key and returns it in a byte array format
    /// </summary>
    /// <returns></returns>
    public byte[] CreateAESByteKey()
    {
        using var aes = new AesCryptoServiceProvider();
        aes.KeySize = theKeySize;
        aes.Mode = cipherMode;
        aes.GenerateKey();
        return aes.Key;
    }


    public (string aesKey, string hmacKey) GetKeyAndIV(string password)
    {
        var passwordSalt = Encoding.ASCII.GetBytes(DateTime.UtcNow.ToString("dddd, dd MMMM yyyy"));
        var hmacSalt = Encoding.ASCII.GetBytes(DateTime.UtcNow.ToString("ddd, dd MMM yyy"));

        var normalizePasswordSalt = helpers.GetByte(passwordSalt);
        var normalizehmacSalt = helpers.GetByte(hmacSalt);
        // Derive the passkey from a hash of the passwordBytes plus salt with the number of hashing rounds.
        var deriveKey = new Rfc2898DeriveBytes(password, normalizePasswordSalt, 10000);
        var deriveHMAC = new Rfc2898DeriveBytes(password, normalizehmacSalt, 10000);

        // This gives us a derived byte key from our passwordBytes.
        var aes256Key = deriveKey.GetBytes(32);
        var hmacKey = deriveHMAC.GetBytes(32);

        return (Convert.ToBase64String(aes256Key), Convert.ToBase64String(hmacKey));
    }
}