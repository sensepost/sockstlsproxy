using StreamExtended.Network;
using StreamExtended;
using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Proxy
{
    internal class Socks5Proxy: ISocksProxy
    {
        async Task<ConnectionInfos> ISocksProxy.Connect(TcpClient client, byte[] data, 
            CustomBufferedStream clientStream, DefaultBufferPool bufferPool)
        {
            Console.WriteLine("[*] SOCKS5 Incoming...");
            await SendSocks5AuthReply(client);

            var _data = new byte[8192];
            await clientStream.ReadAsync(_data, 0, _data.Length);

            Socks5Handler request = await Socks5Handler.FromBytes(_data);

            Console.WriteLine("[+] Connecting to the destination >> " + request.DestinationAddress + "/" + request.DestinationPort);

            await SendSocks5ConnectReply(client, true, request);

            ClientHelloInfo clientSslHelloInfo = await SslTools.PeekClientHello(clientStream, bufferPool);

            return new ConnectionInfos(
                null,
                request.DestinationAddress.ToString(),
                (ushort)request.DestinationPort,
                clientSslHelloInfo
            );
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
    }
}
