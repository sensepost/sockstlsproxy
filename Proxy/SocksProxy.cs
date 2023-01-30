using StreamExtended;
using StreamExtended.Network;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Proxy
{
    internal class SocksProxy
    {
        private readonly int _bindPort;
        private readonly bool _useClientCert;
        private readonly X509Certificate _clientCertificate;
        private readonly IPAddress _bindAddress;
        private readonly CancellationTokenSource _tokenSource;
        private readonly X509Certificate _serverCertificate;

        public SocksProxy(IPAddress bindAddress = null, int bindPort = 1080, bool useClientCert = false, string clientCertName = null, string serverCertName = "MySslSocketCertificate")
        {
            _bindPort = bindPort;
            _bindAddress = bindAddress ?? IPAddress.Any;
            _tokenSource = new CancellationTokenSource();
            _serverCertificate = getServerCert(serverCertName);
            _useClientCert = useClientCert;

            if (_useClientCert)
            {
                _clientCertificate = getClientCert(clientCertName);
            }
        }

        private static X509Certificate getServerCert(string serverCertName)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            X509Certificate2 foundCertificate = null;
            foreach (X509Certificate2 currentCertificate
               in store.Certificates)
            {
                if (currentCertificate.IssuerName.Name
                   != null && currentCertificate.IssuerName.
                   Name.Equals("CN=" + serverCertName))
                {
                    foundCertificate = currentCertificate;
                    break;
                }
            }

            return foundCertificate;
        }

        private static X509Certificate getClientCert(string name)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            X509Certificate2 foundCertificate = null;
            foreach (X509Certificate2 currentCertificate
               in store.Certificates)
            {
                if (currentCertificate.IssuerName.Name
                   != null && currentCertificate.SubjectName.
                   Name.StartsWith("CN=" + name))
                {
                    foundCertificate = currentCertificate;
                    break;
                }
            }

            return foundCertificate;
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

            if (version == 4)
            {
                await SendConnectReply(client, true);

                Socks4Handler request = await Socks4Handler.FromBytes(data);

                Console.WriteLine("[+] Connecting to the destination >> " + request.DestinationAddress + "/" + request.DestinationPort);

                // connect to destination
                var destination = new TcpClient(request.DestinationAddress.ToString(), request.DestinationPort);

                var clientSslHelloInfo = await SslTools.PeekClientHello(clientStream, bufferPool);
                await ProcessData(client, clientStream, destination, request.Hostname, request.DestinationAddress.ToString(), _tokenSource, clientSslHelloInfo);
            }
            else
            {
                Console.WriteLine("[-] SOCKS5 Incoming...");
                await SendSocks5AuthReply(client);

                var _data = new Byte[8192];
                await clientStream.ReadAsync(_data, 0, _data.Length);

                Socks5Handler request = await Socks5Handler.FromBytes(_data);

                Console.WriteLine("[+] Connecting to the destination >> " + request.DestinationAddress + "/" + request.DestinationPort);

                // connect to destination
                var destination = new TcpClient(request.DestinationAddress.ToString(), request.DestinationPort);

                await SendSocks5ConnectReply(client, true, request);

                var clientSslHelloInfo = await SslTools.PeekClientHello(clientStream, bufferPool);
                await ProcessData(client, clientStream, destination, null, request.DestinationAddress.ToString(), _tokenSource, clientSslHelloInfo);
            }
        }

        private async Task ProcessData(TcpClient client, CustomBufferedStream clientStream, TcpClient destination, string hostname, string destinationAddress, CancellationTokenSource tokenSource, ClientHelloInfo clientSslHelloInfo)
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
                    if (!_useClientCert)
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

        private async Task SendConnectReply(TcpClient client, bool success)
        {
            var reply = new byte[]
            {
                0x00,
                success ? (byte)0x5a : (byte)0x5b,
                0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            };

            // Get a client stream for reading and writing. 
            NetworkStream stream = client.GetStream();

            // Send the message to the connected TcpServer. 
            stream.Write(reply, 0, reply.Length);
        }

        private async Task SendSocks5AuthReply(TcpClient client)
        {
            // Establish auth methods that client selected = 0 - No Auth, 1 - GSAPPI, 2 - Username/Password
            //var nmethods = (int)data[1];
            //var methods = new ArrayList();
            //for (int i = 0; i < nmethods; i++)
            //{
            //methods.Add((int)data[2 + i]);
            //}

            // Send auth selection reply 
            // +----+--------+
            // |VER | METHOD |
            // +----+--------+
            // | 1  | 1      |
            // +----+--------+
            var reply = new byte[]
            {
                    0x05, // VER = 05
                    0x00, // 00 = No authentication
            };

            // Get a client stream for reading and writing. 
            NetworkStream stream = client.GetStream();

            // Send the message to the connected TcpServer. 
            stream.Write(reply, 0, reply.Length);
        }

        private async Task SendSocks5ConnectReply(TcpClient client, bool success, Socks5Handler request)
        {
            // Send connect reply
            // +----+-----+-------+------+----------+----------+
            // | VER | REP | RSV | ATYP | BND.ADDR | BND.PORT |
            // +----+-----+-------+------+----------+----------+
            // | 1   | 1   | X'00' | 1  | Variable | 2        |
            // +----+-----+-------+------+----------+----------+

            var reply = new byte[]
             {
                0x05, // VER = 05
                success ? (byte)0x00 : (byte)0x05, // 00 = success
                0x00, // RSV
                (byte)request.AddressType,
                request.DestinationAddress.GetAddressBytes()[0],
                request.DestinationAddress.GetAddressBytes()[1],
                request.DestinationAddress.GetAddressBytes()[2],
                request.DestinationAddress.GetAddressBytes()[3],
                0x00,
                (byte)request.DestinationPort
             };

            // Get a client stream for reading and writing. 
            NetworkStream stream = client.GetStream();

            // Send the message to the connected TcpServer. 
            stream.Write(reply, 0, reply.Length);
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
