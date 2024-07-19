using IdentityStore.Models;
using IdentityStore.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityStore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CryptographyController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public CryptographyController(IConfiguration configuration)
        {
            _configuration = configuration;
        }


        [HttpPost("publickey")]
        public async Task<IActionResult> GetPublicKey()
        {
            var publickey = _configuration["RSA:PublicKey"];

            if (publickey != null)
                return Ok(publickey);
            else
                return StatusCode(500, "Configuration error, public-key was not set in the configuration.");
        }
    }
}
