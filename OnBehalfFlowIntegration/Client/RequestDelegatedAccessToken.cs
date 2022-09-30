using System.Text.Json;

namespace OnBehalfFlowIntegration.Client;

public static class RequestDelegatedAccessToken
{
    public static async Task<OboSuccessResponse?> GetDelegatedApiTokenObo(
        GetDelegatedApiTokenOboModel reqData)
    {
        if (reqData.OboHttpClient == null)
            throw new ArgumentException("Httpclient missing, is null");

        // Content-Type: application/x-www-form-urlencoded
        var oboTokenExchangeBody = new[]
        {
            new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            new KeyValuePair<string, string>("client_id", reqData.ClientId),
            new KeyValuePair<string, string>("client_secret", OboExtentions.ToSha256(reqData.ClientSecret)),
            new KeyValuePair<string, string>("assertion", reqData.AccessToken),
            new KeyValuePair<string, string>("scope", reqData.Scope),
            new KeyValuePair<string, string>("requested_token_use", "on_behalf_of"),
        };

        var response = await reqData.OboHttpClient.PostAsync(reqData.EndpointUrl, new FormUrlEncodedContent(oboTokenExchangeBody));

        if (response.IsSuccessStatusCode)
        {
            var tokenResponse = await JsonSerializer.DeserializeAsync<OboSuccessResponse>(
            await response.Content.ReadAsStreamAsync());
            return tokenResponse;
        }
        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            // error
            var tokenResponse = await JsonSerializer.DeserializeAsync<OboErrorResponse>(
           await response.Content.ReadAsStreamAsync());
        }
        else
        {
            // unknown error, log
        }

        return null;
    }
}
