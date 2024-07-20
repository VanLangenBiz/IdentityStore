namespace IdentityStore.Services
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

            var issuer = _configuration["Jwt:Issuer"] ?? throw new InvalidDataException("Issuer not found in configuration");
            var audience = _configuration["Jwt:Audience"] ?? throw new InvalidDataException("Audience not found in configuration");
            var privateKeyBase64 = _configuration["Jwt:PrivateKey"] ?? throw new InvalidDataException("PrivateKey not found in configuration");
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

        public TokenValidationResult ValidateToken(string token, out ClaimsPrincipal claimsPrincipal)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var publicKey = Convert.FromBase64String(Environment.GetEnvironmentVariable("Jwt:PublicKey"));

            var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(publicKey, out _);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidAudience = _configuration["Jwt:Issuer"],
                IssuerSigningKey = new RsaSecurityKey(rsa)
            };

            claimsPrincipal = null;
            SecurityToken validatedToken;

            try
            {
                claimsPrincipal = tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
                return TokenValidationResult.Valid;
            }
            catch (SecurityTokenExpiredException)
            {
                return TokenValidationResult.Expired;
            }
            catch (SecurityTokenInvalidSignatureException)
            {
                return TokenValidationResult.InvalidSignature;
            }
            catch (SecurityTokenInvalidIssuerException)
            {
                return TokenValidationResult.InvalidIssuer;
            }
            catch (SecurityTokenInvalidAudienceException)
            {
                return TokenValidationResult.InvalidAudience;
            }
            catch
            {
                return TokenValidationResult.OtherError;
            }
        }

    }
}