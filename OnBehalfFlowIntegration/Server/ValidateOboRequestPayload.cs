
namespace OnBehalfFlowIntegration.Server;

public static class ValidateOboRequestPayload
{
    public static (bool Valid, string Reason) IsValid(OboPayload oboPayload, OboConfiguration oboConfiguration)
    {
        if(!oboPayload.RequestedTokenUse.ToLower().Equals("on_behalf_of"))
        {
            return (false, "requested_token_use parameter has an incorrect value, expected on_behalf_of");
        };

        if (!oboPayload.GrantType.ToLower().Equals("urn:ietf:params:oauth:grant-type:jwt-bearer"))
        {
            return (false, "grant_type parameter has an incorrect value, expected urn:ietf:params:oauth:grant-type:jwt-bearer");
        };

        return (true, string.Empty);
    }
}
