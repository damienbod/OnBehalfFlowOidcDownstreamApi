using System.Text.Json.Serialization;

namespace OnBehalfFlowIntegration;

public class OboPayload
{
    [JsonPropertyName("grant_type")]
    public string GrantType {get;set;} = string.Empty;

    [JsonPropertyName("client_id")]
    public string ClientId { get; set; } = string.Empty;

    [JsonPropertyName("client_secret")]
    public string ClientSecret { get; set; } = string.Empty;

    [JsonPropertyName("assertion")]
    public string Assertion { get; set; } = string.Empty;

    [JsonPropertyName("scope")]
    public string Scope { get; set; } = string.Empty;

    [JsonPropertyName("requested_token_use")]
    public string RequestedTokenUse { get; set; } = string.Empty;
}
