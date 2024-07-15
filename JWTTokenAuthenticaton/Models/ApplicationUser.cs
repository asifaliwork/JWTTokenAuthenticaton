using Microsoft.AspNetCore.Identity;
using Microsoft.Identity.Client;

namespace JWTTokenAuthenticaton.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string Name { get; set; }

        public string RefreshToken { get; set; }

        public DateTime RefreshTokenExpiry { get; set; }
    }
}
