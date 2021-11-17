//////////////////////////////////////////////////////////////////////////////////////////////////
//																			
//  MODULE          :   variable.cs
//  VERSION         :   $VERSION
//  DESCRIPTION     :   AESHMAC512 is an encryption wrapper that utilise GZIP, AES CBC and HMAC SHA512
//                     
//																			
///////////////////////////////////////////////////////////////////////////////////////////////////	

namespace Cryptography.Lib;

/// <summary>
/// AESHMAC512 is an encryption wrapper that utilise GZIP, AES CBC and HMAC SHA512
/// </summary>
public partial class AESHMAC512 : AES
{
    /// <summary>
    /// Stores the length of the IVs
    /// </summary>
    private const int ivSize = 16;

    /// <summary>
    /// Timestamp length (is a double not a string)
    /// </summary>
    private const int timestampSize = 8;
}