using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace OnBehalfFlowIntegration.Server;

public static class ValidateOboRequestPayload
{
    public static (bool Valid, string Reason) IsValid(OboPayload oboPayload, OboConfiguration oboConfiguration)
    {
        if(!oboPayload.requested_token_use.ToLower().Equals("on_behalf_of"))
        {
            return (false, "obo requested_token_use parameter has an incorrect value, expected on_behalf_of");
        };

        if (!oboPayload.grant_type.ToLower().Equals("urn:ietf:params:oauth:grant-type:jwt-bearer"))
        {
            return (false, "obo grant_type parameter has an incorrect value, expected urn:ietf:params:oauth:grant-type:jwt-bearer");
        };

        if (!oboPayload.client_id.Equals(oboConfiguration.ClientId))
        {
            return (false, "obo client_id parameter has an incorrect value");
        };

        if (!oboPayload.client_secret.Equals(OboExtentions.ToSha256(oboConfiguration.ClientSecret)))
        {
            return (false, "obo client secret parameter has an incorrect value");
        };

        if (!oboPayload.scope.ToLower().Equals(oboConfiguration.ScopeForNewAccessToken.ToLower()))
        {
            return (false, "obo scope parameter has an incorrect value");
        };

        return (true, string.Empty);
    }

    public static (bool Valid, string Reason, ClaimsPrincipal? ClaimsPrincipal) 
            ValidateTokenSignature(string jwtToken, OboConfiguration oboConfiguration, ICollection<SecurityKey> signingKeys)
    {
        try
        {
            var validationParameters = new TokenValidationParameters
            {
                RequireExpirationTime = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(1),
                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = signingKeys,
                ValidateIssuer = true,
                ValidIssuer = oboConfiguration.AccessTokenAuthority,
                ValidateAudience = true, 
                ValidAudience = oboConfiguration.AccessTokenAudience
            };

            ISecurityTokenValidator tokenValidator = new JwtSecurityTokenHandler();

            var claimsPrincipal = tokenValidator.ValidateToken(jwtToken, validationParameters, out var _);

            return (true, string.Empty, claimsPrincipal);
        }
        catch (Exception ex)
        {
            return (false, $"Access Token Authorization failed {ex.Message}", null);
        }
    }

    public static string GetPreferredUserName(ClaimsPrincipal claimsPrincipal)
    {
        string preferredUsername = string.Empty;
        var preferred_username = claimsPrincipal.Claims.FirstOrDefault(t => t.Type == "preferred_username");
        if (preferred_username != null)
        {
            preferredUsername = preferred_username.Value;
        }

        return preferredUsername;
    }

    public static string GetAzpacr(ClaimsPrincipal claimsPrincipal)
    {
        string azpacr = string.Empty;
        var azpacrClaim = claimsPrincipal.Claims.FirstOrDefault(t => t.Type == "azpacr");
        if (azpacrClaim != null)
        {
            azpacr = azpacrClaim.Value;
        }

        return azpacr;
    }

    public static string GetAzp(ClaimsPrincipal claimsPrincipal)
    {
        string azp = string.Empty;
        var azpClaim = claimsPrincipal.Claims.FirstOrDefault(t => t.Type == "azp");
        if (azpClaim != null)
        {
            azp = azpClaim.Value;
        }

        return azp;
    }
}
