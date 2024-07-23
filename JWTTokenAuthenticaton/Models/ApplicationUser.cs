using Microsoft.AspNetCore.Identity;
using Microsoft.Identity.Client;

namespace JWTTokenAuthenticaton.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string Name { get; set; } = string.Empty;

        public string RefreshToken { get; set; } = string.Empty;

        public DateTime RefreshTokenExpiry { get; set; } 
    }
}
