﻿using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace OnBehalfFlowIntegration.Server;

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

        var subject = new ClaimsIdentity(new[] {
            new Claim("sub", payload.Sub),
            new Claim("scope", payload.Scope),
            new Claim("act", $"{{ \"sub\": \"{payload.OriginalClientId}\" }}", JsonClaimValueTypes.Json )
        });

        if (payload.ClaimsPrincipal != null)
        {
            var name = ValidateOboRequestPayload.GetPreferredUserName(payload.ClaimsPrincipal);
            var azp = ValidateOboRequestPayload.GetAzp(payload.ClaimsPrincipal);
            var azpacr = ValidateOboRequestPayload.GetAzpacr(payload.ClaimsPrincipal);

            if (!string.IsNullOrEmpty(name))
                subject.AddClaim(new Claim("name", name));

            if (!string.IsNullOrEmpty(name))
                subject.AddClaim(new Claim("azp", azp));

            if (!string.IsNullOrEmpty(name))
                subject.AddClaim(new Claim("azpacr", azpacr));
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = subject,
            Expires = DateTime.UtcNow.AddHours(1),
            IssuedAt = DateTime.UtcNow,
            Issuer = "https://localhost:44318/",
            Audience = payload.Audience,
            SigningCredentials = signingCredentials,
            TokenType = "at+jwt"
        };

        tokenDescriptor.AdditionalHeaderClaims ??= new Dictionary<string, object>();

        if (!tokenDescriptor.AdditionalHeaderClaims.ContainsKey("alg"))
        {
            tokenDescriptor.AdditionalHeaderClaims.Add("alg", alg);
        }

        var token = tokenHandler.CreateToken(tokenDescriptor);

        return tokenHandler.WriteToken(token);
    }
}
