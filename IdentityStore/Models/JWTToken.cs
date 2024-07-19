namespace IdentityStore.Models
{
    using System;

    public class JWTToken
    {
        public int Id { get; set; } // Voeg deze regel toe voor de primaire sleutel
        //public int TokenId { get; set; }
        public string UserId { get; set; }
        public ApplicationUser User { get; set; }
        public string Token { get; set; }
        public DateTime ExpiresAt { get; set; }
        public DateTime CreatedAt { get; set; }
    }

}
