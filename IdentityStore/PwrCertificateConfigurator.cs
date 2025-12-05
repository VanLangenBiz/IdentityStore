using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using System.Security.Cryptography.X509Certificates;


namespace IdentityStore
{

    public static class PwrCertificateConfigurator
    {
        /// <summary>
        /// Configureert Kestrel HTTPS endpoints op basis van appsettings.json,
        /// met gebruik van TPM-beveiligd PFX-wachtwoordbeheer.
        /// </summary>
        public static void Configure(KestrelServerOptions options, IConfiguration config)
        {
            // Laad TPM/AES wachtwoord
            byte[] aesKey = PasswordEncryptionLoader.GetOrCreateDecryptionKey();
            string pfxPassword = Convert.ToBase64String(aesKey);

            var endpoints = config.GetSection("Kestrel:PWREndpoints");

            foreach (var endpoint in endpoints.GetChildren())
            {
                string url = endpoint.GetValue<string>("Url");
                string certPath = endpoint.GetValue<string>("Certificate:Path");
                bool requireClientCert = endpoint.GetValue<string>("ClientCertificateMode")?
                    .Equals("RequireCertificate", StringComparison.OrdinalIgnoreCase)
                    ?? false;

                if (string.IsNullOrWhiteSpace(url) || string.IsNullOrWhiteSpace(certPath))
                    continue;

                var uri = new Uri(url);
                int port = uri.Port;

                Console.WriteLine($"[PWR-CERT] Binding endpoint: {url}");
                Console.WriteLine($"[PWR-CERT] Using certificate: {certPath}");

                var cert = new X509Certificate2(certPath, pfxPassword);

                Console.WriteLine("[PWR-CERT] Certificate loaded. Has private key: " + cert.HasPrivateKey);
                Console.WriteLine("[PWR-CERT] Private key provider: " + cert.GetRSAPrivateKey()?.GetType().FullName);

                options.ListenAnyIP(port, listen =>
                {
                    listen.UseHttps(https =>
                    {
                        https.ServerCertificate = cert;

                        if (requireClientCert)
                            https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                    });
                });
            }
        }

    }

}
