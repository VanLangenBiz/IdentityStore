namespace IdentityStore.Services
{
    using IdentityStore.Models;
    using Microsoft.AspNetCore.Identity;
    using System;
    using System.Collections.Generic;
    using System.Data;
    using System.Linq;
    using System.Threading.Tasks;

    public interface IRoleManagementService
    {
        Task<bool> AddUserToRoleAsync(string userId, string role);
        Task<bool> RemoveUserFromRoleAsync(string userId, string role);
        Task<ApplicationUser?> FindUserByName(string username);
        Task<bool> CreateRole(string role);
        Task<bool> DeleteRole(string role);
    }

    public class RoleManagementService : IRoleManagementService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleManagementService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task<ApplicationUser?> FindUserByName(string username)
        {
            return await _userManager.FindByNameAsync(username);
        }

        public async Task<bool> AddUserToRoleAsync(string userId, string role)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return false; // Gebruiker niet gevonden
            }

            var roleExists = await _roleManager.RoleExistsAsync(role);
            if (!roleExists)
            {
                return false; // Rol bestaat niet
            }

            var result = await _userManager.AddToRoleAsync(user, role);
            return result.Succeeded;
        }

        public async Task<bool> RemoveUserFromRoleAsync(string userId, string role)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return false; // Gebruiker niet gevonden
            }

            var result = await _userManager.RemoveFromRoleAsync(user, role);
            return result.Succeeded;
        }

        public async Task<bool> CreateRole(string role)
        {
            var result = await _roleManager.CreateAsync(new IdentityRole
            {
                Name = role
            });

            return result.Succeeded;
        }

        public async Task<bool> DeleteRole(string role)
        {
            var identityRole = await _roleManager.FindByNameAsync(role);
            if (identityRole == null)
                return false;

            var result = await _roleManager.DeleteAsync(identityRole);

            return result.Succeeded;
        }
    }

}
