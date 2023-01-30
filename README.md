# C# SOCKS4/4A/5 Proxy + TLS Modification

## Introduction

This project contains a Visual Studio C# project for a SOCKS4/4A/5 proxy that adds a user-specified client SSL certificate to HTTPS traffic.

The proxy code aligns as close as possible to the SOCKS4/4A and SOCKS5 RFCs:

* https://en.wikipedia.org/wiki/SOCKS
* http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol
* https://www.rfc-editor.org/rfc/rfc1928

## Limitations

1. The SOCKS5 capability of the proxy is currently limited to ```no authentication``` or then auth method ```X'00'``` only.
2. The proxy only supports TCP connections currently.

The aforementioned limitations could easily be corrected through code modification within the ```SocksProxy.cs``` and associated ```Socks4Handler.cs``` or ```Socks5Handler.cs``` files. Key changes would involve the initial handshake logic for the SOCKS5 handler (i.e. to support authentication). Simimarly, references to ```TcpClient``` would need to be replaced with an UDP alternative.

## Why This Project?

Imagine a scenario where you have code execution or RDP access to a target Windows workstation. Upon inspection, you notice that a client SSL certificate has been loaded and is employed by some application(s) on the workstation. You navigate to the Windows Certificate Store (```certmgr.exe```), but find that the certificate cannot be exported.

Instead of exporting the certificate, the TLS SOCKS proxy presented in this project allows you to pass HTTPS traffic to the target workstation and have it locally add the client SSL certificate to the communication. Since the HTTPS traffic is technically originating from the target workstation; the SOCKS proxy will have access to the client SSL certificate without requiring a private key - as the proxy is already running in the user's context.

**Note: Think of this proxy as being equivalent to how Burp Suite allows you to add a client SSL certificate to HTTPS traffic being passed through it. Albeit, with this custom C# implementation; you don't need to export/import the client SSL certificate.**

## Usage Instructions

The proxy is meant to be compiled with Visual Studio, and currently targets .NET framework 4.8.2.

Once compiled, a single binary ```Proxy.exe``` will be available that can either be deployed directly to a target workstation, or that could be executed in-memory.

The usage instructions are as follows:

```powershell
PS C:\SocksTLSProxy\> .\Proxy.exe -h
Usage: Proxy.exe <bind address> <bind port> <use cert> <CN of client cert> <CN of server cert>
```

By default, the SOCKS proxy binds to ```0.0.0.0``` and ```TCP/1080``` on the target workstation. These properties can be modified through the command-line arguments (see example above).

The proxy by default depends on a self-signed server certificate, that should be generated and installed on the target workstation:

```powershell
Makecert -r -pe -n "CN=MySslSocketCertificate" -b 01/01/2015 -e 01/01/2025 -sk exchange -ss my
```

**Note 1: The CN of the server certificate can be changed, albeit the modified CN would need to be passed as an argument when invoking the proxy.**

**Note 2: If a server-compatible certificate is already available on the workstation, then it could be used instead. This could assist with OPSEC and reduce the footprint left on the workstation.**

Lastly, the proxy requires the CN of the client SSL certificate (i.e. ```BadSSL Client Certificate```) that should be added to all HTTPS traffic. This will be highly-dependent on the target workstation and the certificate being targeted. The following serves as a complete example how the SOCKS TLS proxy could be invoked:

```powershell
PS C:\SocksTLSProxy\> .\Proxy.exe 0.0.0.0 1080 true "BadSSL Client Certificate" "MySslSocketCertificate"
```

**Note: The proxy will only have access to the current user's context. As such, the client certificate needs to be available under Certificate - Current User -> Personal -> Certificates.**

**OPSEC: The logic of the SOCKS proxy has not been obfuscated in any way. Prior to usage, it would be advisable for some obfuscation to be applied i.e. using [Obfuscator](https://github.com/obfuscar/obfuscar)**

With the proxy deployed and running, your local ```proxychains``` configuration file (```/etc/proxychains.conf```) can be updated to either target the SOCKS4 or SOCKS5 capability of the now remotely running SOCKS proxy:

```text
[ProxyList]
# add proxy here ...
socks4 	<target workstation ip> 1080
---- OR ----
socks5 	<target workstation ip> 1080
```

Alternatively, a local Burp Suite installation could be configured to automatically route traffic to the awaiting SOCKS proxy.

## References and Resource Material

This project would not have been possible without the insights, code snippets and examples shared by several online resources:

* https://en.wikipedia.org/wiki/SOCKS
* http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol
* https://www.rfc-editor.org/rfc/rfc1928
* https://github.com/cfcs/ocaml-socks/tree/master/rfc
* https://rastamouse.me/socks4a-proxy-in-csharp/
* https://github.com/ring04h/s5.go
* https://github.com/enthus1ast/nimSocks/blob/master/nimSocks/server.nim
* https://gist.github.com/whoisjeeva/b685ee4df9fb78832a8b4eda59fc7b64
* https://gist.github.com/zHaytam/3730d512eb5eaf37fb3bd3d176185541
