using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;

namespace JWTTokenAuthenticaton.Data
{
    public class JwtTokenLifetimeManager : ITokenLifetimeManager
    {
        private static readonly ConcurrentDictionary<string, DateTime> DisavowedSignatures = new();

        public bool ValidateTokenLifetime(DateTime? notBefore,
                                           DateTime? expires,
                                           SecurityToken securityToken,
                                           TokenValidationParameters validationParameters) =>
           securityToken is JwtSecurityToken token &&
           token.ValidFrom <= DateTime.UtcNow &&
           token.ValidTo >= DateTime.UtcNow &&
           DisavowedSignatures.ContainsKey(token.RawSignature) is false;

        public void SignOut(SecurityToken securityToken)
        {
            if (securityToken is JwtSecurityToken token)
                DisavowedSignatures.TryAdd(token.RawSignature, token.ValidTo);

            foreach ((string? key, DateTime _) in DisavowedSignatures.Where(x => x.Value < DateTime.UtcNow))
                DisavowedSignatures.TryRemove(key, out DateTime _);
        }
    }
    
}
