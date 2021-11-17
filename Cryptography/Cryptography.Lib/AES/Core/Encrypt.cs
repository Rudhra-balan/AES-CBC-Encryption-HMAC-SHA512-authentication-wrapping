//////////////////////////////////////////////////////////////////////////////////////////////////
//																			
//  MODULE          :   Encrypt.cs
//  VERSION         :   $VERSION
//  DESCRIPTION     :   Encryption Functions 
//                      encrypt the data and all initialization into a series of arrays based on the
//                      password and the data.
//                      
//																			
///////////////////////////////////////////////////////////////////////////////////////////////////

namespace Cryptography.Lib;

public partial class AES
{
    // encrypt the data and all initialization into a series of arrays based on the

    public string EncryptToString(object plainText)
    {
        helpers.PrintSection("Encryption");
        var privateKey = helpers.CreateKey($"{DateTime.UtcNow:yyyy-MMMM-dd}");
        helpers.Print("Private Key", privateKey);

        var (aes256Key, hmacKey) = GetKeyAndIV(privateKey);
        helpers.Print("HMAC Salt", hmacKey);
        helpers.Print("Aes Key", aes256Key);
        var encryptString = EncryptToString(plainText, aes256Key, hmacKey);
        helpers.Print("Encrypt String", aes256Key);
        return encryptString;
    }


    // encrypt the data and all initialization into a series of arrays based on the
    // password and the data.
    public string EncryptToString(string password, object plainText)
    {
        var (aes256Key, hmacKey) = GetKeyAndIV(password);
        return EncryptToString(plainText, aes256Key, hmacKey);
    }


    /// <summary>
    /// Encrypts the data specified and returns it in a base64 string format
    /// </summary>
    /// <param name="data"></param>
    /// <param name="key"></param>
    /// <param name="IV"></param>
    /// <returns></returns>
    public string EncryptToString(object data, object key, object IV)
    {
        //Checks we have the valid data for encrypting            
        var theKey = helpers.KeyValidation(key);
        var theIV = helpers.IVValidaton(IV);

        //Serialises the data into a byte[]
        var theData = helpers.SerializeToBytes(data);

        //Encrypts the serialised data
        var returnData = Encrypt(theData, theKey, theIV);

        //Returns a base64 string as its an encrypted byte[]
        return Convert.ToBase64String(returnData);
    }


    // encrypt the data 
    public byte[] EncryptToBytes(object plainText)
    {
        var privateKey = helpers.CreateKey($"{DateTime.UtcNow:yyyy-MMMM-dd}");
        var (aes256Key, hmacKey) = GetKeyAndIV(privateKey);
        return EncryptToBytes(plainText, aes256Key, hmacKey);
    }

    // encrypt the data and all initialization into a series of arrays based on the
    // password and the data.
    public byte[] EncryptToBytes(string password, object plainText)
    {
        var (aes256Key, hmacKey) = GetKeyAndIV(password);

        return EncryptToBytes(plainText, aes256Key, hmacKey);
    }

    /// <summary>
    /// Encrypts the data specified and returns it in a byte array format
    /// </summary>
    /// <param name="data"></param>
    /// <param name="key"></param>
    /// <param name="IV"></param>
    /// <returns></returns>
    public byte[] EncryptToBytes(object data, object key, object IV)
    {
        //Checks we have the valid data for encrypting
        var theKey = helpers.KeyValidation(key);
        var theIV = helpers.IVValidaton(IV);

        //Serialises the data into a byte[]
        var theData = helpers.SerializeToBytes(data);

        //Encrypts the data and returns it as a byte[]
        return Encrypt(theData, theKey, theIV);
    }
}