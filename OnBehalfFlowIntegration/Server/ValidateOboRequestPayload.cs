using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace OnBehalfFlowIntegration.Server;

public static class ValidateOboRequestPayload
{
    public static (bool Valid, string Reason) IsValid(OboPayload oboPayload, OboConfiguration oboConfiguration)
    {
        if(!oboPayload.RequestedTokenUse.ToLower().Equals("on_behalf_of"))
        {
            return (false, "obo requested_token_use parameter has an incorrect value, expected on_behalf_of");
        };

        if (!oboPayload.GrantType.ToLower().Equals("urn:ietf:params:oauth:grant-type:jwt-bearer"))
        {
            return (false, "obo grant_type parameter has an incorrect value, expected urn:ietf:params:oauth:grant-type:jwt-bearer");
        };

        if (!oboPayload.ClientId.Equals(oboConfiguration.ClientId))
        {
            return (false, "obo client_id parameter has an incorrect value");
        };

        if (!oboPayload.ClientSecret.Equals(OboExtentions.ToSha256(oboConfiguration.ClientSecret)))
        {
            return (false, "obo client secret parameter has an incorrect value");
        };

        if (!oboPayload.Scope.ToLower().Equals(oboConfiguration.ScopeForNewAccessToken.ToLower()))
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
}
