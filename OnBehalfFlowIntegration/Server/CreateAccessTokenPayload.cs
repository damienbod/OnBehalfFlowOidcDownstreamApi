using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace OnBehalfFlowIntegration.Server
{
    public static class CreateDelegatedAccessTokenPayload
    {
        public static string GenerateJwtTokenAsync(CreateDelegatedAccessTokenPayloadModel payload)
        {
            SigningCredentials signingCredentials = new X509SigningCredentials(payload.SigningCredentials);

            var alg = signingCredentials.Algorithm;

            //{
            //  "alg": "RS256",
            //  "kid": "....",
            //  "typ": "at+jwt",
            //}

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                // TODO add claims as required if authorized
                Subject = new ClaimsIdentity(new[] {
                    new Claim("sub", payload.Sub),
                    new Claim("username", payload.UserName) ,
                    new Claim("scope", payload.Scope)
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                IssuedAt = DateTime.UtcNow,
                Issuer = "https://localhost:44318/",
                Audience = payload.Audience,
                SigningCredentials = signingCredentials,
                TokenType = "at+jwt"
            };

            if (tokenDescriptor.AdditionalHeaderClaims == null)
            {
                tokenDescriptor.AdditionalHeaderClaims = new Dictionary<string, object>();
            }

            if (!tokenDescriptor.AdditionalHeaderClaims.ContainsKey("alg"))
            {
                tokenDescriptor.AdditionalHeaderClaims.Add("alg", alg);
            }

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
    }
}
