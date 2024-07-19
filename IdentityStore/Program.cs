
using IdentityStore.Data;
using IdentityStore.Models;
using IdentityStore.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
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
                // Verkrijg de privésleutel en openbare sleutel als Base64-strings
                string privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
                string publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());

                // Print de sleutels naar de console (of sla ze op in bestanden)
                Console.WriteLine("Store these keys in the User Secrets");
                Console.WriteLine();
                Console.WriteLine($"\"RSA:PrivateKey\": \"{privateKey}\",");
                Console.WriteLine($"\"RSA:PublicKey\": \"{publicKey}\"");
                Console.WriteLine();
            }
        }

        public static void Main(string[] args)
        {
            // ## Use this method to generate new RSA keys. Save them in the secrets.json
            // GenerateKeys();

            var builder = WebApplication.CreateBuilder(args);

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

            var privateKeyBase64 = builder.Configuration["RSA:PrivateKey"] ?? throw new InvalidDataException("PrivateKey not found in configuration");
            var publicKeyBase64 = builder.Configuration["RSA:PublicKey"] ?? throw new InvalidDataException("PublicKey not found in configuration");

            // Converteer de Base64-strings naar byte-arrays
            var privateKeyBytes = Convert.FromBase64String(privateKeyBase64);
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
                    ValidAudience = builder.Configuration["Jwt:Issuer"],
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
    }
}