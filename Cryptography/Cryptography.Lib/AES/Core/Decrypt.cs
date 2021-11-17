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

public partial class AES
{
    /// <summary>
    /// Decrypts the data and returns it in a format which has been specified
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="data"></param>
    /// <param name="key"></param>
    /// <param name="IV"></param>
    /// <returns></returns>
    public T DecryptToType<T>(object data, object key, object IV)
    {
        //Checks we have the valid data for decrypting
        var encryptedData = helpers.EncryptedDataValidation(data);
        var theKey = helpers.KeyValidation(key);
        var theIV = helpers.IVValidaton(IV);

        //Decrypts the data and puts it into the variable
        var decryptedData = Decrypt(encryptedData, theKey, theIV);

        //Returns the deserialised byte[] back into the object type it was originally
        return helpers.DerializeFromBytes<T>(decryptedData);
    }

    public T DecryptToType<T>(object data, string password)
    {
        var (key, IV) = GetKeyAndIV(password);
        //Checks we have the valid data for decrypting
        var encryptedData = helpers.EncryptedDataValidation(data);
        var theKey = helpers.KeyValidation(key);
        var theIV = helpers.IVValidaton(IV);

        //Decrypts the data and puts it into the variable
        var decryptedData = Decrypt(encryptedData, theKey, theIV);

        //Returns the deserialised byte[] back into the object type it was originally
        return helpers.DerializeFromBytes<T>(decryptedData);
    }


    public T DecryptToType<T>(object data)
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
        var decryptedData = Decrypt(encryptedData, theKey, theIV);

        //Returns the deserialised byte[] back into the object type it was originally
        return helpers.DerializeFromBytes<T>(decryptedData);
    }
}