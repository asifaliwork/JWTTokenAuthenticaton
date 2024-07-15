namespace JWTTokenAuthenticaton.Models
{
    public class RefreshToken
    {
        public string JwtToken { get; set; }
        public string refreshToken { get; set; }
    }
}
