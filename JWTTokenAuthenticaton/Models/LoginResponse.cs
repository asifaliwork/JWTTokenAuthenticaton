using System.ComponentModel.DataAnnotations;

namespace JWTTokenAuthenticaton.Models
{
    public class LoginResponse
    {
        public string? Status { get; set; }
        public string? Token { get; set; }
        public string? Message { get; set; }
        public string? RefreshToken { get; set; }
    }
}
