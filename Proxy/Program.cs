using System.Threading.Tasks;
using System;
using CommandLine;

namespace Proxy
{
    internal class Program
    {
        internal class Options
        {
            [Option('a', "address", Default = "0.0.0.0", HelpText = "Bind address")]
            public string Address { get; set; }
            [Option('p', "port", Default = (ushort)1080, HelpText = "Bind port")]
            public ushort Port { get; set; }
            [Option("auth", Default = false, HelpText = "Use Client Certificate Authentication")]
            public bool UseClientCertificate { get; set; } = false;
            [Option('c', "client-cert", Required = false, HelpText = "CN of Client Cert")]
            public string ClientCertName { get; set; }
            [Option('s', "socks-cert", Default = "MySslSocketCertificate", HelpText = "CN of Socks Proxy Cert")]
            public string SocksCertName { get; set; }
        }

        static async Task Main(string[] args)
        {
            Options options = null;
            CommandLine.Parser.Default.ParseArguments<Options>(args)
            .WithParsed(opts =>
            {
                if (opts.UseClientCertificate && string.IsNullOrEmpty(opts.ClientCertName))
                {
                    Console.WriteLine("CN of Client Cert (-c option) is required when using client certificate authentication");
                    return;
                }
                options = opts;
            });

            if(options != null)
            {
                await RunProxy(options);
            }
        }

        static async Task RunProxy(Options options)
        {
            SocksProxy socksProxy = new SocksProxy(
                options.Address,
                options.Port,
                options.UseClientCertificate,
                options.ClientCertName,
                options.SocksCertName
            );
            await socksProxy.Start();
        }
    }
}
