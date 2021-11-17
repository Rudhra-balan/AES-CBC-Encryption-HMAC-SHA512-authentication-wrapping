//////////////////////////////////////////////////////////////////////////////////////////////////
//																			
//  MODULE          :   Decrypt.cs
//  VERSION         :   $VERSION
//  DESCRIPTION     :   Decryption Functions 
//                      Decrypts the data and returns it in a format which has been specified
//                      
//                      
///////////////////////////////////////////////////////////////////////////////////////////////////

namespace Cryptography.Lib;

public partial class AESHMAC512
{
    /// <summary>
    /// Decrypts the data and returns it in a format which has been specified
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="data"></param>
    /// <param name="password"></param>
    /// <returns></returns>
    public new T DecryptToType<T>(object data, string password)
    {
        var (cryptKey, authKey) = GetKeyAndIV(password);
        //Checks we have the valid data for decrypting
        var encryptedData = helpers.EncryptedDataValidation(data);
        var normalKey = helpers.KeyValidation(cryptKey);
        var authenticationKey = helpers.KeyValidation(authKey);

        //Decrypts the data and puts it into the variable
        var decryptedData = CoreDecrypt(encryptedData, normalKey, authenticationKey);

        //Returns the deserialised byte[] back into the object type it was originally
        return helpers.DerializeFromBytes<T>(decryptedData);
    }

    /// <summary>
    /// Decrypts the data and returns it in a format which has been specified
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="data"></param>
    /// <param name="cryptKey"></param>
    /// <param name="authKey"></param>
    /// <returns></returns>
    public new T DecryptToType<T>(object data, object cryptKey, object authKey)
    {
        //Checks we have the valid data for decrypting
        var encryptedData = helpers.EncryptedDataValidation(data);
        var normalKey = helpers.KeyValidation(cryptKey);
        var authenticationKey = helpers.KeyValidation(authKey);

        //Decrypts the data and puts it into the variable
        var decryptedData = CoreDecrypt(encryptedData, normalKey, authenticationKey);

        //Returns the deserialised byte[] back into the object type it was originally
        return helpers.DerializeFromBytes<T>(decryptedData);
    }


    /// <summary>
    /// Decrypts the data and returns it in a format which has been specified
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="data"></param>
    /// <param name="password"></param>
    /// <param name="maxSecondsDifference"></param>
    /// <returns></returns>
    public T DecryptToType<T>(object data, string password, int maxSecondsDifference)
    {
        var (cryptKey, authKey) = GetKeyAndIV(password);
        //Checks we have the valid data for decrypting
        var encryptedData = helpers.EncryptedDataValidation(data);
        var normalKey = helpers.KeyValidation(cryptKey);
        var authenticationKey = helpers.KeyValidation(authKey);

        //Decrypts the data and puts it into the variable
        var decryptedData = CoreDecrypt(encryptedData, normalKey, authenticationKey, maxSecondsDifference);

        //Returns the deserialised byte[] back into the object type it was originally
        return helpers.DerializeFromBytes<T>(decryptedData);
    }

    /// <summary>
    /// Decrypts the data and returns it in a format which has been specified
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="data"></param>
    /// <param name="cryptKey"></param>
    /// <param name="authKey"></param>
    /// <param name="maxSecondsDifference"></param>
    /// <returns></returns>
    public T DecryptToType<T>(object data, object cryptKey, object authKey, int maxSecondsDifference)
    {
        //Checks we have the valid data for decrypting
        var encryptedData = helpers.EncryptedDataValidation(data);
        var normalKey = helpers.KeyValidation(cryptKey);
        var authenticationKey = helpers.KeyValidation(authKey);

        //Decrypts the data and puts it into the variable
        var decryptedData = CoreDecrypt(encryptedData, normalKey, authenticationKey, maxSecondsDifference);

        //Returns the deserialised byte[] back into the object type it was originally
        return helpers.DerializeFromBytes<T>(decryptedData);
    }

    public new T DecryptToType<T>(object data)
    {
        helpers.PrintSection("Decryption");
        var privateKey = helpers.CreateKey($"{DateTime.UtcNow:yyyy-MMMM-dd}");
        helpers.Print("Private Key", privateKey);

        var (key, IV) = GetKeyAndIV(privateKey);
        helpers.Print("HMAC Salt", IV);
        helpers.Print("Aes Key", key);

        //Checks we have the valid data for decrypting
        var encryptedData = helpers.EncryptedDataValidation(data);
        var theKey = helpers.KeyValidation(key);
        var theIV = helpers.IVValidaton(IV);

        //Decrypts the data and puts it into the variable
        var decryptedData = CoreDecrypt(encryptedData, theKey, theIV);

        helpers.Print("Decrpted Text", helpers.DerializeFromBytes<string>(decryptedData));

        //Returns the deserialised byte[] back into the object type it was originally
        return helpers.DerializeFromBytes<T>(decryptedData);
    }

    public T DecryptToType<T>(object data, int maxSecondsDifference = 0)
    {
        helpers.PrintSection("Decryption");
        var privateKey = helpers.CreateKey($"{DateTime.UtcNow:yyyy-MMMM-dd}");
        helpers.Print("Private Key", privateKey);

        var (key, IV) = GetKeyAndIV(privateKey);
        helpers.Print("HMAC Salt", IV);
        helpers.Print("Aes Key", key);

        //Checks we have the valid data for decrypting
        var encryptedData = helpers.EncryptedDataValidation(data);
        var theKey = helpers.KeyValidation(key);
        var theIV = helpers.IVValidaton(IV);

        //Decrypts the data and puts it into the variable
        var decryptedData = CoreDecrypt(encryptedData, theKey, theIV, maxSecondsDifference);

        helpers.Print("Decrpted Text", helpers.DerializeFromBytes<string>(decryptedData));

        //Returns the deserialised byte[] back into the object type it was originally
        return helpers.DerializeFromBytes<T>(decryptedData);
    }
}