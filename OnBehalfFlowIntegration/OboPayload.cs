using System.Text.Json.Serialization;

namespace OnBehalfFlowIntegration
{
    public class OboPayload
    {
        [JsonPropertyName("expiresIn")]
        public string GrantType {get;set;}

        [JsonPropertyName("client_id")]
        public string ClientId { get; set; }

        [JsonPropertyName("client_secret")]
        public string ClientSecret { get; set; }

        [JsonPropertyName("assertion")]
        public string Assertion { get; set; }

        [JsonPropertyName("scope")]
        public string Scope { get; set; }

        [JsonPropertyName("requested_token_use")]
        public string RequestedTokenUse { get; set; }
    }
}
