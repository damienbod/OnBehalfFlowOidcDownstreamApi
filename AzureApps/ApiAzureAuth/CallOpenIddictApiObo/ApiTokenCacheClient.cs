using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using OnBehalfFlowIntegration;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ApiAzureAuth;

public class ApiTokenCacheClient
{
    private readonly ILogger<ApiTokenCacheClient> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IOptions<DownstreamApi> _downstreamApiConfigurations;

    private static readonly object _lock = new();
    private readonly IDistributedCache _cache;

    private const int cacheExpirationInDays = 1;

    private class AccessTokenItem
    {
        public string AccessToken { get; set; } = string.Empty;
        public DateTime ExpiresIn { get; set; }
    }

    public ApiTokenCacheClient(
        IOptions<DownstreamApi> downstreamApiConfigurations,
        IHttpClientFactory httpClientFactory,
        ILoggerFactory loggerFactory,
        IDistributedCache cache)
    {
        _downstreamApiConfigurations = downstreamApiConfigurations;
        _httpClientFactory = httpClientFactory;
        _logger = loggerFactory.CreateLogger<ApiTokenCacheClient>();
        _cache = cache;
    }

    public async Task<string> GetApiTokenObo(string clientId, 
        string scope, string clientSecret, string aadAccessToken)
    {
        var accessToken = GetFromCache(clientId);

        if (accessToken != null)
        {
            if (accessToken.ExpiresIn > DateTime.UtcNow)
            {
                return accessToken.AccessToken;
            }
            else
            {
                // remove  => NOT Needed for this cache type
            }
        }

        _logger.LogDebug("GetApiToken new from STS for {api_name}", clientId);

        // add
        var newAccessToken = await GetApiTokenOboAad( clientId,  scope,  clientSecret, aadAccessToken);
        AddToCache(clientId, newAccessToken);

        return newAccessToken.AccessToken;
    }

    private async Task<AccessTokenItem> GetApiTokenOboAad(string clientId, 
        string scope, string clientSecret, string aadAccessToken)
    {
        try
        {
            var oboClient = _httpClientFactory.CreateClient();
            oboClient.BaseAddress = new Uri(_downstreamApiConfigurations.Value.IdentityProviderUrl);

            // Content-Type: application/x-www-form-urlencoded
            var oboTokenExchangeBody = new[]
            {
                new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("client_secret", clientSecret),
                new KeyValuePair<string, string>("assertion", aadAccessToken),
                new KeyValuePair<string, string>("scope", scope),
                new KeyValuePair<string, string>("requested_token_use", "on_behalf_of"),
            };
            
            var response = await oboClient.PostAsync("/connect/obotoken", new FormUrlEncodedContent(oboTokenExchangeBody));

            if (response.IsSuccessStatusCode)
            {
                var tokenResponse = await JsonSerializer.DeserializeAsync<OboSuccessResponse>(
                await response.Content.ReadAsStreamAsync());

                if (tokenResponse != null)
                {
                    return new AccessTokenItem
                    {
                        ExpiresIn = DateTime.UtcNow.AddSeconds(tokenResponse.ExpiresIn),
                        AccessToken = tokenResponse.AccessToken
                    };
                }
            }

            return new AccessTokenItem
            {
                ExpiresIn = DateTime.UtcNow,// DateTime.UtcNow.AddSeconds(tokenResponse.ExpiresIn),
                AccessToken = "aaaa" // tokenResponse.AccessToken
            };
                
        }
        catch (Exception e)
        {
            _logger.LogError("Exception {e}", e);
            throw new ApplicationException($"Exception {e}");
        }
    }

    private void AddToCache(string key, AccessTokenItem accessTokenItem)
    {
        var options = new DistributedCacheEntryOptions().SetSlidingExpiration(TimeSpan.FromDays(cacheExpirationInDays));

        lock (_lock)
        {
            _cache.SetString(key, JsonSerializer.Serialize(accessTokenItem), options);
        }
    }

    private AccessTokenItem? GetFromCache(string key)
    {
        var item = _cache.GetString(key);
        if (item != null)
        {
            return JsonSerializer.Deserialize<AccessTokenItem>(item);
        }

        return null;
    }
}