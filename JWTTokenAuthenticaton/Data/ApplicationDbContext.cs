using JWTTokenAuthenticaton.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWTTokenAuthenticaton.Data
{

    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
            var tokenLifetimeManager = new JwtTokenLifetimeManager();
        }
    }
}
