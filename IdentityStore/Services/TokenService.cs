﻿namespace IdentityStore.Services
{
    using IdentityStore.Models;
    using Microsoft.Extensions.Configuration;
    using Microsoft.IdentityModel.Tokens;
    using System;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Text;

    public class TokenService
    {
        private readonly IConfiguration _configuration;

        public TokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GenerateToken(ApplicationUser user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var issuer = _configuration["Issuer"] ?? throw new InvalidDataException("Issuer not found in configuration");
            var audience = _configuration["Audience"] ?? throw new InvalidDataException("Audience not found in configuration");
            var privateKeyBase64 = _configuration["RSA:PrivateKey"] ?? throw new InvalidDataException("PrivateKey not found in configuration");
            var privateKeyBytes = Convert.FromBase64String(privateKeyBase64);

            var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(privateKeyBytes, out _);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Iss, issuer),
                    new Claim(JwtRegisteredClaimNames.Aud, audience),
                    new Claim(ClaimTypes.Role, "Administrator") // for example
                }),
                Expires = DateTime.UtcNow.AddMinutes(60),
                SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}