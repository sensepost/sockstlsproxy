using System.Net;
using System.Threading.Tasks;
using System;

namespace Proxy
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            if (args.Length == 0) {
                SocksProxy socks4Proxy = new SocksProxy();
                await socks4Proxy.Start();
            } else if (args.Length < 5  || 5 < args.Length || args[0] == "-h" || args[0] == "--help")
            {
                Console.WriteLine("Usage: Proxy.exe <bind address> <bind port> <use cert> <CN of client cert> <CN of server cert>");
                return;
            } else
            {
                IPAddress address = IPAddress.Parse(args[0]);
                SocksProxy socks4Proxy = new SocksProxy(address, int.Parse(args[1]), bool.Parse(args[2]), args[3], args[4]);
                await socks4Proxy.Start();
            }
        }
    }
}
