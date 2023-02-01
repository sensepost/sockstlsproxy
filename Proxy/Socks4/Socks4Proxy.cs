using StreamExtended;
using StreamExtended.Network;
using System;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Proxy
{
    internal class Socks4Proxy : ISocksProxy
    {

        async Task<ConnectionInfos> ISocksProxy.Connect(TcpClient client, byte[] data, 
            CustomBufferedStream clientStream, DefaultBufferPool bufferPool)
        {
            Console.WriteLine("[*] SOCKS4/4a Incoming...");
            await SendConnectReply(client, true);

            Socks4Handler request = await Socks4Handler.FromBytes(data);

            Console.WriteLine("[+] Connecting to the destination >> " + request.DestinationAddress + "/" + request.DestinationPort);

            // connect to destination

            ClientHelloInfo clientSslHelloInfo = await SslTools.PeekClientHello(clientStream, bufferPool);

            return new ConnectionInfos(
                request.Hostname, 
                request.DestinationAddress.ToString(), 
                (ushort)request.DestinationPort,
                clientSslHelloInfo
            );
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
    }
}
