using System;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Proxy
{
    internal class CertificateUtil
    {
        public static X509Certificate GetServerCert(string serverCertName)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            X509Certificate2 certificate = null;
            foreach (X509Certificate2 currentCertificate in store.Certificates)
            {
                if (currentCertificate.IssuerName.Name != null &&
                    currentCertificate.IssuerName.Name.Equals("CN=" + serverCertName))
                {
                    certificate = currentCertificate;
                    break;
                }
            }

            return certificate;
        }

        public static X509Certificate MakeCert(string certName)
        {
            Console.WriteLine($"[*] Creating self-signed certificate {certName}");
            try
            {
                RSA key = RSA.Create(); // generate asymmetric key pair
                CertificateRequest req = new CertificateRequest("cn=" + certName, key, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5));

                if(!cert.HasPrivateKey)
                {
                    cert = cert.CopyWithPrivateKey(key);
                }

                var persistable = new X509Certificate2(cert.Export(X509ContentType.Pfx), "", X509KeyStorageFlags.PersistKeySet);

                using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                {
                    store.Open(OpenFlags.ReadWrite);
                    store.Add(persistable);
                }

                Console.WriteLine($"[+] Certificate {certName} created and Added to My store");
                return persistable;
            } catch(Exception ex)
            {
                Console.WriteLine($"[-] Error creating certificate {certName}");
                Console.WriteLine(ex);
                return null;
            }
        }

        public static X509Certificate GetOrCreateServerCert(string serverCertName)
        {
            X509Certificate cert = GetServerCert(serverCertName);
            if(cert == null)
            {
                Console.WriteLine($"[-] Server cert {serverCertName} not found in my store.");
                cert = MakeCert(serverCertName);
            }

            return cert;
        }

        public static X509Certificate GetClientCert(string name)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            foreach (X509Certificate2 currentCertificate in store.Certificates)
            {
                if (currentCertificate.IssuerName.Name != null &&
                    currentCertificate.SubjectName.Name.StartsWith("CN=" + name))
                {
                    return currentCertificate;
                }
            }

            return null;
        }
    }
}
