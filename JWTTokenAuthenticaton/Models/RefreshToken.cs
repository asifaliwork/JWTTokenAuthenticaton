namespace JWTTokenAuthenticaton.Models
{
    public class RefreshToken
    {
       // public int Id { get; set; }
        public string Token { get; set; } = string.Empty;
        public string Refreshtoken { get; set; } = string.Empty;
       // public bool Revoked { get; set; }
    }
}
