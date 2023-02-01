using System.Net;
using System.Threading.Tasks;

namespace Proxy
{
    internal class Socks5Handler
    {
        public CommandCode Command { get; private set; }
        public int DestinationPort { get; private set; }
        public int AddressType { get; private set; }
        public IPAddress DestinationAddress { get; private set; }

        public static async Task<Socks5Handler> FromBytes(byte[] raw)
        {
            var request = new Socks5Handler
            {
                Command = (CommandCode)raw[1],
                // raw[2] = RESERVED
                AddressType = (int)raw[3],
                DestinationAddress = new IPAddress(new[] { raw[4], raw[5], raw[6], raw[7] }),
                DestinationPort = raw[9] | raw[8] << 8,                
            };            

            return request;
        }

        public enum CommandCode : byte
        {
            StreamConnection = 0x01,
            PortBinding = 0x02
        }
    }
}
