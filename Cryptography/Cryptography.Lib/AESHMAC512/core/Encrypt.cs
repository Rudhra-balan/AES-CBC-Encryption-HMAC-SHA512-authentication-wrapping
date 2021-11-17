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

public partial class AESHMAC512
{
    //######################################################
    //#######           Encryption Functions         #######
    //######################################################

    // encrypt the data and all initialization into a series of arrays based on the

    public new string EncryptToString(object plainText)
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
    public new string EncryptToString(string password, object plainText)
    {
        var (aes256Key, hmacKey) = GetKeyAndIV(password);

        return EncryptToString(plainText, aes256Key, hmacKey);
    }

    /// <summary>
    /// Encrypts the data specified and returns it in a base64 string format
    /// </summary>
    /// <param name="data"></param>
    /// <param name="cryptKey"></param>
    /// <param name="authKey"></param>
    /// <returns></returns>
    public new string EncryptToString(object data, object cryptKey, object authKey)
    {
        var normalKey = helpers.KeyValidation(cryptKey);
        var authenticationKey = helpers.KeyValidation(authKey);

        //Serialises the data into a byte[]
        var theData = helpers.SerializeToBytes(data);

        //Encrypts the serialised data
        var returnData = CoreEncrypt(theData, normalKey, authenticationKey);

        //Returns a base64 string as its an encrypted byte[]
        return Convert.ToBase64String(returnData);
    }

    // encrypt the data and all initialization into a series of arrays based on the
    // password and the data.
    public new byte[] EncryptToBytes(string password, object plainText)
    {
        var (aes256Key, hmacKey) = GetKeyAndIV(password);

        return EncryptToBytes(plainText, aes256Key, hmacKey);
    }


    // encrypt the data 
    public new byte[] EncryptToBytes(object plainText)
    {
        var privateKey = helpers.CreateKey($"{DateTime.UtcNow:yyyy-MMMM-dd}");
        var (aes256Key, hmacKey) = GetKeyAndIV(privateKey);
        return EncryptToBytes(plainText, aes256Key, hmacKey);
    }

    /// <summary>
    /// Encrypts the data specified and returns it in a byte array format
    /// </summary>
    /// <param name="data"></param>
    /// <param name="cryptKey"></param>
    /// <param name="authKey"></param>
    /// <returns></returns>
    public new byte[] EncryptToBytes(object data, object cryptKey, object authKey)
    {
        var normalKey = helpers.KeyValidation(cryptKey);
        var authenticationKey = helpers.KeyValidation(authKey);

        //Serialises the data into a byte[]
        var theData = helpers.SerializeToBytes(data);

        //Encrypts the serialised data
        var returnData = CoreEncrypt(theData, normalKey, authenticationKey);


        return returnData;
    }
}