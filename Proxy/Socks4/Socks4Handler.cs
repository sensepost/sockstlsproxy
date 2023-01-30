using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Proxy
{
    internal class Socks4Handler
    {
        public CommandCode Command { get; private set; }
        public int DestinationPort { get; private set; }
        public IPAddress DestinationAddress { get; private set; }

        public string Hostname { get; private set; }

        public static async Task<Socks4Handler> FromBytes(byte[] raw)
        {
            var request = new Socks4Handler
            {
                Command = (CommandCode)raw[1],
                DestinationPort = raw[3] | raw[2] << 8,
                DestinationAddress = new IPAddress(new[] { raw[4], raw[5], raw[6], raw[7] })
            };

            // if this is SOCKS4a
            if (request.DestinationAddress.ToString().StartsWith("0.0.0."))
            {
                var bytes = new List<byte>();
                for (int i = 9; i < raw.Length; i++)
                {
                    if (raw[i] != 0x00)
                    {
                        bytes.Add(raw[i]);
                    }
                }
                
                var domain = Encoding.UTF8.GetString(bytes.ToArray());
                request.Hostname = domain;
                var lookup = await Dns.GetHostAddressesAsync(domain);

                // get the first ipv4 address
                request.DestinationAddress = lookup.First(i => i.AddressFamily == AddressFamily.InterNetwork);
            }

            return request;
        }

        public enum CommandCode : byte
        {
            StreamConnection = 0x01,
            PortBinding = 0x02
        }
    }
}
