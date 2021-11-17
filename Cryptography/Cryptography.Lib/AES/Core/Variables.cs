//////////////////////////////////////////////////////////////////////////////////////////////////
//																			
//  MODULE          :   variable.cs
//  VERSION         :   $VERSION
//  DESCRIPTION     :   AES is an encryption wrapper that utilises GZIP and AES CBC
//                     
//																			
///////////////////////////////////////////////////////////////////////////////////////////////////		

using System.Security.Cryptography;

namespace Cryptography.Lib;

/// <summary>
/// AES is an encryption wrapper that utilises GZIP and AES CBC
/// </summary>
public partial class AES
{
    /// <summary>
    /// Stores the length of the key requirement
    /// </summary>
    private const int theKeySize = 256;

    /// <summary>
    /// Stores the ciphermode to use in AES: CBC
    /// </summary>
    private const CipherMode cipherMode = CipherMode.CBC;

    /// <summary>
    /// Stores the helper functions to do validation, compression etc
    /// </summary>
    protected readonly Helpers helpers = null;

    public AES()
    {
        helpers = new Helpers();
    }
}