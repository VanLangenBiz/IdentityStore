namespace IdentityStore.Data
{
    using IdentityStore.Models;
    using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
    using Microsoft.EntityFrameworkCore;

    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<JWTToken> JWTTokens { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<JWTToken>()
                .HasOne(t => t.User)
                .WithMany(u => u.JWTTokens)
                .HasForeignKey(t => t.UserId);
        }
    }

}
