
using System.Reflection;
using System.Text;
using Cryptography.Console;
using Cryptography.Lib;
using Newtonsoft.Json;

AssemblyInfo projectAssemblyInfo = new AssemblyInfo(Assembly.GetEntryAssembly());

string plainText = JsonConvert.SerializeObject(projectAssemblyInfo);

AESHMAC512 aeshmac512 = new AESHMAC512();

var length = Encoding.UTF8.GetBytes(plainText).Length;
Console.WriteLine("{0} ({1} bytes, {2} bits): ", "Plain Text", length, length * 8);
Console.WriteLine(plainText);
Console.WriteLine();


Console.WriteLine(DateTime.UtcNow);

var encryptString = aeshmac512.EncryptToString(plainText);



var i = aeshmac512.DecryptToType<string>(encryptString, 2);
Console.WriteLine(i);

Console.ReadLine();

