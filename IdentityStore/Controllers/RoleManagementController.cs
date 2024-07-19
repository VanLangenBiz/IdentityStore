namespace IdentityStore.Controllers
{
    using IdentityStore.Models;
    using IdentityStore.Services;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.Threading.Tasks;
    using System.IdentityModel.Tokens.Jwt;

    [Route("api/[controller]")]
    [ApiController]
    public class RoleManagementController : ControllerBase
    {
        private readonly IRoleManagementService _roleManagementService;

        public RoleManagementController(IRoleManagementService roleManagementService)
        {
            _roleManagementService = roleManagementService;
        }

        private DateTime? GetTokenExpiryDate(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            if (tokenHandler.CanReadToken(token))
            {
                var jwtToken = tokenHandler.ReadJwtToken(token);
                var expClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Exp);

                if (expClaim != null && long.TryParse(expClaim.Value, out var exp))
                {
                    // Convert the expiry date from Unix time to DateTime
                    var expiryDate = DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime;
                    return expiryDate;
                }
            }
            return null; // Return null if the token is invalid or does not contain an expiry date
        }

        private string? GetJwtTokenFromRequest()
        {
            var authHeader = HttpContext.Request.Headers["Authorization"].FirstOrDefault();
            if (authHeader != null && authHeader.StartsWith("Bearer "))
            {
                return authHeader.Substring("Bearer ".Length).Trim();
            }

            return null;
        }

        [Authorize(Roles = "Administrator")] // Alleen geautoriseerde gebruikers met rol "Administrator" hebben toegang
        [HttpPost("findUserIdByName")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> FindUserIdByName(string username)
        {
            DateTime? expireDate = null;

            var token = GetJwtTokenFromRequest();

            if (token != null)
            {
                expireDate = GetTokenExpiryDate(token);
            }

            var result = await _roleManagementService.FindUserByName(username);
            if (result != null)
            {
                //return Ok(expireDate.HasValue ? expireDate.Value : "no date found");
                return Ok(result);
            }
            else
            {
                return BadRequest($"Username not found");
            }
        }

        [HttpPost("createRole")]
        public async Task<IActionResult> CreateRole(string role)
        {
            var result = await _roleManagementService.CreateRole(role);

            if (result)
            {
                return Ok("Role created");
            }
            else
            {
                return BadRequest($"Role not found");
            }
        }


        [HttpPost("addUserToRole")]
        public async Task<IActionResult> AddUserToRole(AddUserToRoleDto model)
        {
            var result = await _roleManagementService.AddUserToRoleAsync(model.UserId, model.Role);
            if (result)
            {
                return Ok($"Gebruiker met ID {model.UserId} is toegevoegd aan rol {model.Role}");
            }
            else
            {
                return BadRequest($"Kon gebruiker niet toevoegen aan rol {model.Role}");
            }
        }

        [HttpPost("removeUserFromRole")]
        public async Task<IActionResult> RemoveUserFromRole(RemoveUserFromRoleDto model)
        {
            var result = await _roleManagementService.RemoveUserFromRoleAsync(model.UserId, model.Role);
            if (result)
            {
                return Ok($"Gebruiker met ID {model.UserId} is verwijderd uit rol {model.Role}");
            }
            else
            {
                return BadRequest($"Kon gebruiker niet verwijderen uit rol {model.Role}");
            }
        }
    }

}
