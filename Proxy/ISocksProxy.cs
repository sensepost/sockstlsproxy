using StreamExtended;
using StreamExtended.Network;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Proxy
{
    internal struct ConnectionInfos
    {
        public string Hostname;
        public string DestinationAddress;
        public ushort DestinationPort;
        public ClientHelloInfo ClientHelloInfo;

        public ConnectionInfos(string Hostname, string DestinationAddress, 
            ushort DestinationPort, ClientHelloInfo ClientHelloInfo)
        {
            this.Hostname = Hostname;
            this.DestinationAddress = DestinationAddress;
            this.DestinationPort = DestinationPort;
            this.ClientHelloInfo = ClientHelloInfo;
        }
    }
    internal interface ISocksProxy
    {
        Task<ConnectionInfos> Connect(TcpClient client, byte[] data, 
            CustomBufferedStream clientStream, DefaultBufferPool bufferPool);
    }
}
