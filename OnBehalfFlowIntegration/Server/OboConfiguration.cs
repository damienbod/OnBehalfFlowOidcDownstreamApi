namespace ApiAzureAuth;

public class OboConfiguration
{
    // request parameters
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string ScopeForNewAccessToken { get; set; } = string.Empty;

    // token validation
    public string AccessTokenMetadataAddress { get; set; } = string.Empty;
    public string AccessTokenAuthority { get; set; } = string.Empty;
    public string AccessTokenAudience { get; set; } = string.Empty;

}
