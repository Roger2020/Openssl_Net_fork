using System;


namespace SSLStreamTest
{
	class Program
	{
		static string fileDirectory = Environment.CurrentDirectory;
		static string fileName = "test.pdf";

		static void Main(string[] args)
		{
			try
			{
				TestOneway one = new TestOneway();
				one.TestSync();
			}
			catch (Exception e)
			{
				Console.WriteLine(e.InnerException.Message);
			}
			Console.ReadLine();
		}
	}
}