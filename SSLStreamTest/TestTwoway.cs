using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using OpenSSL.Core;
using OpenSSL.Crypto;
using OpenSSL.SSL;
using OpenSSL.X509;

namespace SSLStreamTest
{
	class TestTwoway
	{

		class ReadAsyncResultState
		{
			public StringBuilder Content = new StringBuilder();
			public int ReadTotalSize = 0;
			public byte[] Buffer;
		}

		static System.Threading.Timer mTime;

		static string fileDirectory = Environment.CurrentDirectory;
		static string fileName = "exeTest.exe";
		private const string uriStrOneway = "https://httpbin.org:443/get";
		private const string uriNginxOneway = "https://localhost:4433/";
		private const string uriNginxOnewayFile = "https://localhost:4431/222.pdf";
		private const string Urlexe = "https://dl.cmbimg.com/download/PB/PBSetup70.exe";

		Uri mReqUri;
		TcpClient mTcp;
		SslStream mSslStream;
		string mRequestLine;
		byte[] requestMsg;


		static StringBuilder readData = new StringBuilder();
		static byte[] buffer = new byte[512];

		public TestTwoway()
		{
			mReqUri = new Uri(Urlexe);
			string hostAndPort = mReqUri.Host + ":" + mReqUri.Port;
			mRequestLine = $"GET {mReqUri.PathAndQuery} HTTP/1.1\r\nHost: {hostAndPort}\r\nConnection: close\r\n\r\n";
			requestMsg = Encoding.UTF8.GetBytes(mRequestLine);
		}

		private void EstablishSSL()
		{
			try
			{
				Console.WriteLine("Client> Connecting to: {0}:{1}", mReqUri.Host, mReqUri.Port);
				mTcp = new TcpClient(mReqUri.Host, mReqUri.Port);
				if (mTcp.Connected)
				{
					mSslStream = new SslStream(mTcp.GetStream(), true, validateRemoteCert, selectClientCertificate);
				}
			}
			catch (Exception e)
			{
				throw e;
			}
		}

		public void TestSync()
		{
			try
			{
				EstablishSSL();

				if (mSslStream == null)
				{
					return;
				}
				X509List clientCertificateList = new X509List();
				clientCertificateList.Add(getFileCert());

				mSslStream.AuthenticateAsClient(
				mReqUri.Host,
				clientCertificateList,
				null,
				SslProtocols.Tls,
				SslStrength.All,
				false);
				Console.WriteLine("Client> CurrentCipher: {0}", mSslStream.Ssl.CurrentCipher.Name);
				Assert.IsTrue(mSslStream.IsAuthenticated);

				//write request
				byte[] requestMsg = Encoding.UTF8.GetBytes(mRequestLine);
				mSslStream.Write(requestMsg, 0, requestMsg.Length);
				mSslStream.Flush();

				//read response
				//case 1.
				//readResponseString(mSslStream);

				//case 2.
				saveFile(mSslStream);

			}
			catch (Exception e)
			{
				throw e;
			}
			finally
			{
				Dispose();
			}
		}

		class autState
		{
			public bool IsAuthenticated = false;
		}
		public void TestAsync()
		{
			try
			{
				EstablishSSL();

				if (mSslStream == null)
				{
					return;
				}
				IAsyncResult state = mSslStream.BeginAuthenticateAsClient(mReqUri.Host, null, null, SslProtocols.Tls, SslStrength.All, false, authenticateAsClientCallBack, null);

				Assert.IsTrue(mSslStream.IsAuthenticated);

				Console.WriteLine($"Thread: 【{Thread.CurrentThread.ManagedThreadId}】");
			}
			catch (Exception e)
			{
				throw e;
			}
		}


		private void readResponseString(SslStream sslStream)
		{
			StringBuilder resp = new StringBuilder();
			int readTotalSize = 0;
			byte[] buffer = new byte[128];//临时读缓存，越小的话受网络影响越轻

			int readCount = -1;
			do
			{
				readCount = sslStream.Read(buffer, 0, buffer.Length);
				Console.WriteLine($"read {readCount} bytes");
				readTotalSize += readCount;
				string part = Encoding.UTF8.GetString(buffer, 0, readCount);
				resp.Append(part);
			} while (readCount > 0);

			if (resp.Length == 0)
			{
				Console.WriteLine("response is null");
			}
			else
			{
				Console.WriteLine(resp.ToString());
			}
		}

		private void authenticateAsClientCallBack(IAsyncResult inResult)
		{
			Console.WriteLine($"Thread: 【{Thread.CurrentThread.ManagedThreadId}】");

			autState obj = (autState)inResult.AsyncState;
			try
			{
				Console.WriteLine("Writting data to the server.");
				mSslStream.EndAuthenticateAsClient(inResult);
				Console.WriteLine("Client> CurrentCipher: {0}", mSslStream.Ssl.CurrentCipher.Name);

				Assert.IsTrue(mSslStream.IsAuthenticated);
				mSslStream.BeginWrite(requestMsg, 0, requestMsg.Length, writeCallBack, null);
			}
			catch (Exception)
			{
				throw;
			}
		}

		private void writeCallBack(IAsyncResult inResult)
		{
			Console.WriteLine($"Thread: 【{Thread.CurrentThread.ManagedThreadId}】");
			try
			{
				Console.WriteLine("Writting data to the server.");
				mSslStream.EndWrite(inResult);

				byte[] buf = new byte[512];
				ReadAsyncResultState stateObj = new ReadAsyncResultState();
				stateObj.Buffer = buf;
				mSslStream.BeginRead(stateObj.Buffer, 0, stateObj.Buffer.Length, readCallBack, stateObj);
			}
			catch (Exception e)
			{
				throw e;
			}
		}


		private void readCallBack(IAsyncResult inResult)
		{
			ReadAsyncResultState stateObj = inResult.AsyncState as ReadAsyncResultState;
			int byteCount = -1;
			try
			{
				Console.WriteLine("reading data from the server.");
				byteCount = mSslStream.EndRead(inResult);
				if (byteCount > 0 /*&& "协议级别的终止条件"*/)
				{
					Console.WriteLine($"read {byteCount} bytes");
					stateObj.ReadTotalSize += byteCount;
					string part = Encoding.UTF8.GetString(stateObj.Buffer, 0, byteCount);
					stateObj.Content.Append(part);
					mSslStream.BeginRead(stateObj.Buffer, 0, stateObj.Buffer.Length, new AsyncCallback(readCallBack), stateObj);
				}
				else
				{
					if (stateObj.Content.Length == 0)
					{
						Console.WriteLine("response is null.");
					}
					else
					{
						Console.WriteLine(stateObj.Content.ToString());
					}
				}
			}
			catch (Exception e)
			{
				throw e;
			}
		}

		private void saveFile(SslStream sslStream)
		{
			string fullFile = createFileName(fileName);
			Stopwatch watch = new Stopwatch();
			watch.Start();

			byte[] buffer = new byte[128];
			int readTotalSize = 0;
			string msg = $"当前读取  {readTotalSize} bytes({readTotalSize / 1024} KB.)";
			try
			{
				mTime = new Timer(printProgress, msg, 0, 3000);

				using (FileStream fs = new FileStream(fullFile, FileMode.OpenOrCreate, FileAccess.ReadWrite))
				{
					int readCount = -1;
					do
					{
						readCount = sslStream.Read(buffer, 0, buffer.Length);
						fs.Write(buffer, 0, readCount);
						readTotalSize += readCount;
					} while (readCount > 0);

					isCpmpleted = true;
					Console.WriteLine($"总读取  {readTotalSize} bytes({readTotalSize / 1024} KB.)");
					Console.WriteLine($"总耗时  {watch.ElapsedMilliseconds}  ms。");
				}
			}
			catch (Exception e)
			{
				throw e;
			}
		}

		bool isCpmpleted = false;

		private void printProgress(object state)
		{
			if (!isCpmpleted)
			{
				Console.WriteLine("downloading......");
			}
		}

		private X509Certificate getFileCert()
		{
			string keyFilePath = @".\rsaCert\client.key";
			BIO bioKey = BIO.File(keyFilePath, "r");
			CryptoKey pk = OpenSSL.Crypto.CryptoKey.FromPrivateKey(bioKey, null);

			string caFilePath = @".\rsaCert\client.crt";
			BIO bioSign = BIO.File(caFilePath, "r");
			X509Certificate signCert = new X509Certificate(bioSign);
			signCert.PrivateKey = pk;
			//Assert.IsTrue(signCert.HasPrivateKey);

			return signCert;
		}

		private bool validateRemoteCert(
			object obj,
			X509Certificate cert,
			X509Chain chain,
			int depth,
			VerifyResult result)
		{
			return true;

			Console.WriteLine("Validate> {0} depth: {1}, result: {2}", cert.Subject, depth, result);
			switch (result)
			{
				case VerifyResult.X509_V_ERR_CERT_UNTRUSTED:
				case VerifyResult.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
				case VerifyResult.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
				case VerifyResult.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
				case VerifyResult.X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
					// Check the chain to see if there is a match for the cert
					var ret = checkCert(cert, chain);
					if (!ret && depth != 0)
					{
						return true;
					}
					return ret;
				case VerifyResult.X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
				case VerifyResult.X509_V_ERR_CERT_NOT_YET_VALID:
					Console.WriteLine("Certificate is not valid yet");
					return false;
				case VerifyResult.X509_V_ERR_CERT_HAS_EXPIRED:
				case VerifyResult.X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
					Console.WriteLine("Certificate is expired");
					return false;
				case VerifyResult.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
					// we received a self signed cert - check to see if it's in our store
					return checkCert(cert, chain);
				case VerifyResult.X509_V_OK:
					return true;
				default:
					return false;
			}
		}
		private bool checkCert(X509Certificate cert, X509Chain chain)
		{
			if (cert == null || chain == null)
				return false;

			foreach (var certificate in chain)
			{
				if (cert == certificate)
					return true;
			}

			return false;
		}

		private X509Certificate selectClientCertificate(
	object sender,
	string targetHost,
	X509List localCerts,
	X509Certificate remoteCert,
	string[] acceptableIssuers)
		{
			Console.WriteLine("SelectClientCertificate> {0}", targetHost);
			//return null;//单向不用选择证书

			//双向
			foreach (var issuer in acceptableIssuers)
			{
				Console.WriteLine("SelectClientCertificate> issuer: {0}", issuer);

				using (var name = new X509Name(issuer))
				{
					foreach (var cert in localCerts)
					{
						Console.WriteLine("SelectClientCertificate> local: {0}", cert.Subject);
						if (cert.Issuer.CompareTo(name) == 0)
						{
							return cert;
						}
						cert.Dispose();
					}
				}
			}
			return null;
		}
		private static string createFileName(string fileName)
		{
			if (!Directory.Exists(fileDirectory))
			{
				Directory.CreateDirectory(fileDirectory);
			}

			string fullFile = Path.Combine(fileDirectory, fileName);
			while (File.Exists(fullFile))
			{
				string[] parts = fileName.Split(new char[] { '.' }, 2);
				parts[0] += "-" + DateTime.Now.Hour + DateTime.Now.Minute + DateTime.Now.Second;
				fileName = parts[0] + "." + parts[1];
				fullFile = Path.Combine(fileDirectory, fileName);
			}
			return fullFile;
		}

		public void Dispose()
		{
			if (mSslStream != null)
			{
				mSslStream.Close();
				mSslStream.Dispose();
			}
			if (mTcp != null)
			{
				mTcp.Close();
			}
		}
	}
}
