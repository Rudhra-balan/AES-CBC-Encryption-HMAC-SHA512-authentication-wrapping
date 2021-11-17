//////////////////////////////////////////////////////////////////////////////////////////////////
//																			
//  MODULE          :   Key.cs
//  VERSION         :   $VERSION
//  DESCRIPTION     :   HMACSHA512 Key and IV Generating Functions 
//                     
//																			
///////////////////////////////////////////////////////////////////////////////////////////////////		

using System.Security.Cryptography;

namespace Cryptography.Lib;

public partial class AESHMAC512
{
    /// <summary>
    /// Generates the HMACSHA512 key and returns it in base64 string format
    /// </summary>
    /// <returns></returns>
    public string CreateHMACAuthenticationStringKey()
    {
        using var hmac = new HMACSHA512();
        var key = hmac.Key;

        //Returns the key in a base64 string format
        return Convert.ToBase64String(key);
    }

    /// <summary>
    /// Generates the HMACSHA512 key and returns it in a byte array format
    /// </summary>
    /// <returns></returns>
    public byte[] CreateHMACAuthenticationByteKey()
    {
        using var hmac = new HMACSHA512();
        //returns a random generate HMACSHA512 key
        return hmac.Key;
    }
}