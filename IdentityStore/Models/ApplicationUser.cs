namespace IdentityStore.Models
{
    using Microsoft.AspNetCore.Identity;
    using System;
    using System.Collections.Generic;

    public class ApplicationUser : IdentityUser
    {
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        public ICollection<JWTToken> JWTTokens { get; set; }
    }
}
