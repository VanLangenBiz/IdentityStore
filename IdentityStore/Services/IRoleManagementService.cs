namespace IdentityStore.Services
{
    using IdentityStore.Models;
    using System.Threading.Tasks;

    public interface IRoleManagementService
    {
        Task<bool> AddUserToRoleAsync(string userId, string role);
        Task<bool> RemoveUserFromRoleAsync(string userId, string role);
        Task<ApplicationUser?> FindUserByName(string username);
        Task<bool> CreateRole(string role);
        Task<bool> DeleteRole(string role);
    }

}
