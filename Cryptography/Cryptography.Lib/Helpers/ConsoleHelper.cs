using System.Text;

namespace Cryptography;

public partial class Helpers
{
    private readonly TextWriter Writer = Console.Out;

    public void Print(string message, string text)
    {
        var length = Encoding.UTF8.GetBytes(text).Length;
        Writer.WriteLine("{0} ({1} bytes, {2} bits): ", message, length, length * 8);
        Writer.WriteLine(text);
        Writer.WriteLine();
    }

    public void Print(string message, byte[] bytes)
    {
        Writer.WriteLine("{0} ({1} bytes, {2} bits): ", message, bytes.Length, bytes.Length * 8);
        Writer.WriteLine(Convert.ToBase64String(bytes));
        Writer.WriteLine();
    }

    public void PrintSection(string message)
    {
        Writer.WriteLine();
        Writer.WriteLine("-------------- {0} --------------", message);
        Writer.WriteLine();
        Writer.WriteLine();
    }
}