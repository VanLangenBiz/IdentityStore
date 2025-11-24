using IdentityStore.Data;
using IdentityStore.Interfaces;
using IdentityStore.Models;
using IdentityStore.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using PwrCsr2;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace IdentityStore
{
    public class Program
    {
        public static async Task SeedRolesAsync(RoleManager<IdentityRole> roleManager)
        {
            string[] roleNames = { "Administrator" };

            foreach (var roleName in roleNames)
            {
                var roleExists = await roleManager.RoleExistsAsync(roleName);
                if (!roleExists)
                {
                    await roleManager.CreateAsync(new IdentityRole(roleName));
                }
            }
        }

        private static void GenerateKeys()
        {
            // use this code to generate a private/public key.
            // Save these keys 
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                // Verkrijg de priv�sleutel en openbare sleutel als Base64-strings
                string privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
                string publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());

                // Print de sleutels naar de console (of sla ze op in bestanden)
                Console.WriteLine("Store these keys in the User Secrets");
                Console.WriteLine();
                Console.WriteLine($"\"Jwt:PrivateKey\": \"{privateKey}\",");
                Console.WriteLine($"\"Jwt:PublicKey\": \"{publicKey}\"");
                Console.WriteLine();
            }
        }

        static string ExportPrivateKeyToPem(RSA rsa)
        {
            var key = rsa.ExportPkcs8PrivateKey();
            return "-----BEGIN PRIVATE KEY-----\n"
                + Convert.ToBase64String(key, Base64FormattingOptions.InsertLineBreaks)
                + "\n-----END PRIVATE KEY-----";
        }

        static void CheckKeyMatch(X509Certificate2 cert, RSA privateKey)
        {
            var certPub = cert.GetRSAPublicKey().ExportRSAPublicKey();
            var privPub = privateKey.ExportRSAPublicKey();

            bool match = certPub.SequenceEqual(privPub);

            Console.WriteLine("PublicKey match? " + match);
        }


        public static void Main(string[] args)
        {
            // ## Use this method to generate new RSA keys. Save them in the secrets.json
            //GenerateKeys();

            var builder = WebApplication.CreateBuilder(args);

            var newCert = SetupCert();

            // HTTPS stuff
            builder.WebHost.ConfigureKestrel((context, options) =>
            {
                //options.ConfigureHttpsDefaults(options => options.ClientCertificateMode = ClientCertificateMode.RequireCertificate);

                // HTTPS listener op jouw Visual Studio HTTPS-port
                options.ListenAnyIP(7048, listen =>
                {
                    listen.UseHttps(newCert);
                });
            });


            // Add services to the container.
            builder.Services.AddTransient<TokenService>(); // Voeg deze regel toe

            // Configure database
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

            // Configure Identity
            builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            // Voeg rolbeheer service toe
            builder.Services.AddScoped<IRoleManagementService, RoleManagementService>();

            var publicKeyBase64 = builder.Configuration["Jwt:PublicKey"] ?? throw new InvalidDataException("Jwt:PublicKey not found in configuration");

            // Converteer de Base64-strings naar byte-arrays
            var publicKeyBytes = Convert.FromBase64String(publicKeyBase64);

            var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(publicKeyBytes, out _);

            // Configure JWT authentication
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = builder.Configuration["Jwt:Issuer"],
                    ValidAudience = builder.Configuration["Jwt:Audience"],
                    IssuerSigningKey = new RsaSecurityKey(rsa), // Public key voor validatie
                };
            });


            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();

            builder.Services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "Your API", Version = "v1" });

                // Voeg JWT bearer authenticatie toe voor Swagger
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = "JWT Authorization header using the Bearer scheme. Example: \"Bearer {token}\"",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer"
                });

                // Definieer de vereiste scopes voor Swagger
                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        new string[] { } // Voeg hier de vereiste rollen of beleidsregels toe
                    }
                });
            });



            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }

        private const string cert = "JeroenLPT.cer";
        private const string chain = "JeroenLPT-chain.cer";
        //private const string caCert = "PWR Machines CA-ca.cer";

        private static X509Certificate2 SetupCert()
        {
            var dataRoot = Environment.GetEnvironmentVariable("PWRDATAROOT")
                         ?? throw new InvalidOperationException("PWRDATAROOT env var ontbreekt.");
            var certPath = Path.Combine(dataRoot, "Certificates");

            if (!Directory.Exists(certPath))
                Directory.CreateDirectory(certPath);

            // AES-key uit configuratie (appsettings, secrets, env var)
            var encPwdEnvName = "PWR_TLS_PFX_PWD_ENC";
            byte[] pwdBytes;
            string pfxPassword;

            // 1) TPM key check (alleen naam + provider)
            CertHelpers.EnsureTpmKeyExists();

            var encPwdBase64 = Environment.GetEnvironmentVariable(encPwdEnvName, EnvironmentVariableTarget.User);

            if (string.IsNullOrEmpty(encPwdBase64))
            {
                // nieuw random password
                pwdBytes = CertHelpers.GenerateRandomChars();
                pfxPassword = Convert.ToBase64String(pwdBytes); // string voor PFX

                var encPwdBytes = CertHelpers.TpmEncrypt(pwdBytes);
                encPwdBase64 = Convert.ToBase64String(encPwdBytes);

                Environment.SetEnvironmentVariable(encPwdEnvName, encPwdBase64, EnvironmentVariableTarget.User);
            }
            else
            {
                var encPwdBytes = Convert.FromBase64String(encPwdBase64);
                pwdBytes = CertHelpers.TpmDecrypt(encPwdBytes);
                pfxPassword = Convert.ToBase64String(pwdBytes);
            }


            // AES key voor private key encryptie = pwdBytes
            var privKeyEncPath = Path.Combine(certPath, "private.key.pem");

            var rsa = PrivateKeyHelper.ReadEncryptedPrivate(privKeyEncPath, pwdBytes);

            var certFilename = Path.Combine(certPath, cert);

            // Leaf certificaat lezen
            string certPem = File.ReadAllText(certFilename);

            // Private key + cert combineren in ��n X509 object
            var leaf = X509Certificate2.CreateFromPem(certPem, ExportPrivateKeyToPem(rsa));

            CheckKeyMatch(leaf, rsa);

            Console.WriteLine("Subject: " + leaf.Subject);
            Console.WriteLine("Thumbprint: " + leaf.Thumbprint);
            Console.WriteLine("Has private key: " + leaf.HasPrivateKey);



            var chainPem = File.ReadAllText(Path.Combine(certPath, chain));
            var chainCerts = new X509Certificate2Collection();


            chainCerts.Add(leaf);

            foreach (var block in chainPem.Split("-----END CERTIFICATE-----"))
            {
                if (block.Contains("BEGIN CERTIFICATE"))
                {
                    var pem = block + "-----END CERTIFICATE-----";
                    chainCerts.Add(X509Certificate2.CreateFromPem(pem));
                }
            }

            var pfxData = chainCerts.Export(X509ContentType.Pkcs12, null); // zonder wachtwoord (toch in-mem)

            var newCert = X509CertificateLoader.LoadPkcs12(
                data: pfxData,
                password: string.Empty
                );

            return newCert;

            //PS C:\programdata\PWR Pack\Certificates> certutil -verify -user -urlfetch jeroenlpt.cer

            // certutil - addstore Root "PWR Root CA.cer"
            // certutil -addstore -user CA "PWR Machines CA.cer"



        }


    }
}