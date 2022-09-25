﻿using Azure.Core;
using IdentityModel.Client;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using System.Net.Http;
using System.Text.Json;
using static IdentityModel.OidcConstants;

namespace ApiAzureAuth;

public class ApiTokenCacheClient
{
    private readonly ILogger<ApiTokenCacheClient> _logger;
    private readonly HttpClient _httpClient;
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
        _httpClient = httpClientFactory.CreateClient();
        _logger = loggerFactory.CreateLogger<ApiTokenCacheClient>();
        _cache = cache;
    }

    public async Task<string> GetApiToken(string clientId, 
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

            var disco = await HttpClientDiscoveryExtensions.GetDiscoveryDocumentAsync(
                _httpClient, _downstreamApiConfigurations.Value.IdentityProviderUrl);


            if (disco.IsError)
            {
                _logger.LogError("disco error Status code: {discoIsError}, Error: {discoError}", disco.IsError, disco.Error);
                throw new ApplicationException($"Status code: {disco.IsError}, Error: {disco.Error}");
            }

            _httpClient.BaseAddress = new Uri(_downstreamApiConfigurations.Value.ApiBaseAddress);

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
            
            var response = await _httpClient.PostAsync(disco.TokenEndpoint, new FormUrlEncodedContent(oboTokenExchangeBody));

            if (response.IsSuccessStatusCode)
            {
                var data = await response.Content.ReadAsStringAsync();

                if (data != null)
                {
                    //return new AccessTokenItem
                    //{
                    //    ExpiresIn = DateTime.UtcNow.AddSeconds(tokenResponse.ExpiresIn),
                    //    AccessToken = tokenResponse.AccessToken
                    //};
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
            _cache.SetString(key, System.Text.Json.JsonSerializer.Serialize(accessTokenItem), options);
        }
    }

    private AccessTokenItem? GetFromCache(string key)
    {
        var item = _cache.GetString(key);
        if (item != null)
        {
            return System.Text.Json.JsonSerializer.Deserialize<AccessTokenItem>(item);
        }

        return null;
    }
}