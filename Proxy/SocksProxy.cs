using StreamExtended;
using StreamExtended.Network;
using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Proxy
{
    internal class SocksProxy
    {
        private readonly IPAddress _bindAddress;
        private readonly ushort _bindPort;
        private readonly bool _useClientAuthentication;
        private readonly X509Certificate _clientCertificate;
        private readonly CancellationTokenSource _tokenSource;
        private readonly X509Certificate _serverCertificate;

        public SocksProxy(string bindAddress = "0.0.0.0", ushort bindPort = 1080, bool useClientAuthentication = false, string clientCertName = null, string serverCertName = "MySslSocketCertificate")
        {
            _bindPort = bindPort;
            try
            {
                _bindAddress = IPAddress.Parse(bindAddress);
            } catch(Exception ex)
            {
                Console.WriteLine($"[*] Invalid IP Address Given, falling back to {IPAddress.Any}");
                _bindAddress = IPAddress.Any;
            }
            _tokenSource = new CancellationTokenSource();
            _serverCertificate = CertificateUtil.GetOrCreateServerCert(serverCertName);
            _useClientAuthentication = useClientAuthentication;

            if (_useClientAuthentication)
            {
                _clientCertificate = CertificateUtil.GetClientCert(clientCertName);
            }
        }


        private static ISocksProxy GetSocksProxy(int version)
        {
            if(version == 4)
            {
                return new Socks4Proxy();
            }

            return new Socks5Proxy();
        }

        public async Task Start()
        {
            Console.WriteLine("[+] --- Starting SOCKS Proxy --- ");

            var listener = new TcpListener(_bindAddress, _bindPort);
            listener.Start(100);

            while (!_tokenSource.IsCancellationRequested)
            {
                // this blocks until a connection is received or token is cancelled
                var client = await listener.AcceptTcpClientAsync();

                // do something with the connected client
                var thread = new Thread(async () => await HandleClient(client));
                thread.Start();
            }

            listener.Stop();
        }

        public void Stop()
        {
            _tokenSource.Cancel();
        }

        public static bool ValidateServerCertificate(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors)
        {
            // Do not allow this client to communicate with unauthenticated servers.
            return true;
        }

        private async Task HandleClient(TcpClient client)
        {
            var endpoint = (IPEndPoint)client.Client.RemoteEndPoint;
            Console.WriteLine("[+] Received Connection << " + endpoint.Address);

            CancellationTokenSource _tokenSource = new CancellationTokenSource();

            var bufferPool = new DefaultBufferPool();
            var clientStream = new CustomBufferedStream(client.GetStream(), bufferPool, 8192);

            var data = new Byte[8192];
            Int32 bytes = await clientStream.ReadAsync(data, 0, data.Length);

            string responseData = Encoding.ASCII.GetString(data, 0, bytes);

            // read the first byte, which is the SOCKS version
            var version = Convert.ToInt32(responseData[0]);

            ISocksProxy socksProxy = GetSocksProxy(version);

            ConnectionInfos infos = await socksProxy.Connect(client, data, clientStream, bufferPool);
            TcpClient destination = new TcpClient(infos.DestinationAddress, infos.DestinationPort);
            await ProcessData(client, clientStream, destination, infos.Hostname, _tokenSource, infos.ClientHelloInfo);
        }

        private async Task ProcessData(TcpClient client, CustomBufferedStream clientStream, TcpClient destination, string hostname, CancellationTokenSource tokenSource, ClientHelloInfo clientSslHelloInfo)
        {
            SslStream sslStream = null;
            if (clientSslHelloInfo != null)
            {
                Console.WriteLine("[+] TLS connection");
                sslStream = new SslStream(clientStream, false);

                try
                {
                    Console.WriteLine("[+] Converting to SSL stream");
                    sslStream.AuthenticateAsServer(_serverCertificate);
                    Console.WriteLine("[+] Done");
                }
                catch (AuthenticationException e)
                {
                    Console.WriteLine("Exception: {0}", e.Message);
                    if (e.InnerException != null)
                    {
                        Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                    }
                    Console.WriteLine("Authentication failed - closing the connection.");
                }
            }

            SslStream sslDestinationStream = null;
            if (clientSslHelloInfo != null)
            {
                sslDestinationStream = new SslStream(destination.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);

                try
                {
                    // Ideally the SNI should be read from the TLS Client Hello; and be used here
                    var sniHostName = clientSslHelloInfo.Extensions["server_name"].Data;
                    if (!_useClientAuthentication)
                    {
                        sslDestinationStream.AuthenticateAsClient(sniHostName);
                    }
                    else
                    {
                        Console.WriteLine("[+] Setting up the client certificate");
                        X509CertificateCollection collection = new X509CertificateCollection();
                        collection.Add(_clientCertificate);

                        sslDestinationStream.AuthenticateAsClient(sniHostName, collection, false);
                        Console.WriteLine("[+] Done");
                    }
                }
                catch (AuthenticationException e)
                {
                    Console.WriteLine("Exception: {0}", e.Message);
                    if (e.InnerException != null)
                    {
                        Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                    }
                    Console.WriteLine("Authentication failed - closing the connection.");
                }
            }

            var globalCount = 0;
            while (!tokenSource.IsCancellationRequested)
            {
                var clientAvailable = DataAvailableClient(client, clientStream, clientSslHelloInfo, tokenSource);
                var destinationAvailable = DataAvailableDestination(destination, tokenSource);

                // read from client
                if (clientAvailable)
                {
                    if (clientSslHelloInfo == null)
                    {
                        Console.WriteLine("[+] Cleartext connection");

                        try
                        {
                            // receive from client
                            var stream = clientStream;
                            var data = new byte[8192];
                            var count = await stream.ReadAsync(data, 0, data.Length);

                            var desStream = destination.GetStream();
                            await desStream.WriteAsync(data, 0, count);
                            Console.WriteLine("[+] Sending data to server.");
                        }
                        catch (System.IO.IOException)
                        {
                            continue;
                        }

                    }
                    else
                    {
                        Console.WriteLine("[+] TLS connection");

                        // receive from client
                        var data = new byte[8192];
                        var count = await sslStream.ReadAsync(data, 0, data.Length);

                        // send to destination
                        await sslDestinationStream.WriteAsync(data, 0, count);
                        Console.WriteLine("[+] Sending data to server.");
                    }
                }

                // read from destination
                if (destinationAvailable)
                {
                    if (clientSslHelloInfo == null)
                    {
                        try
                        {
                            // receive from destination
                            var destinationStream = destination.GetStream();
                            var desData = new byte[8192];
                            var desCount = await destinationStream.ReadAsync(desData, 0, desData.Length);

                            var clientClearStream = client.GetStream();
                            await clientClearStream.WriteAsync(desData, 0, desCount);
                            Console.WriteLine("[+] Receiving data from server.");
                        }
                        catch (System.IO.IOException)
                        {
                            continue;
                        }
                    }
                    else
                    {
                        try
                        {
                            // receive from destination
                            var data = new byte[8192];
                            var count = await sslDestinationStream.ReadAsync(data, 0, data.Length);

                            await sslStream.WriteAsync(data, 0, count);
                            Console.WriteLine("[+] Receiving data from server.");
                        }
                        catch (System.IO.IOException)
                        {
                            continue;
                        }
                    }
                }

                if (!clientAvailable && !destinationAvailable && globalCount == 180)
                {
                    tokenSource.Cancel();
                }

                await Task.Delay(10);
                globalCount++;
            }
            clientStream.Close();
            client.Close();
        }

        public static bool DataAvailableClient(TcpClient client, CustomBufferedStream clientStream, ClientHelloInfo clientSslHelloInfo, CancellationTokenSource tokenSource)
        {
            try
            {
                if (clientSslHelloInfo != null)
                {
                    var ns = client.GetStream();
                    var desData = new byte[8192];
                    ns.ReadAsync(desData, 0, 0);
                    return ns.DataAvailable;

                }
                else
                {
                    var ns = clientStream;
                    var desData = new byte[8192];
                    ns.ReadAsync(desData, 0, 0);
                    return ns.DataAvailable;
                }
            }
            catch (Exception)
            {
                tokenSource.Cancel();
            }
            return false;
        }

        public static bool DataAvailableDestination(TcpClient destination, CancellationTokenSource tokenSource)
        {
            // A bit of a hack to handle RST packets from the destination servers.
            try
            {
                var ns = destination.GetStream();
                var desData = new byte[8192];
                ns.ReadAsync(desData, 0, 0);
                return ns.DataAvailable;
            }
            catch (Exception)
            {
                tokenSource.Cancel();
            }
            return false;
        }
    }
}
