using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpeniddictServer;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json.Serialization;

namespace IdentityProvider.Controllers
{
    public class AuthorizationOboController : Controller
    {
        private IWebHostEnvironment _environment { get; }
        public IConfiguration Configuration { get; }

        public AuthorizationOboController(IConfiguration configuration, IWebHostEnvironment env)
        {
            Configuration = configuration;
            _environment = env;
        }

        [AllowAnonymous]
        [HttpPost("~/connect/obotoken"), Produces("application/json")]
        public async Task<IActionResult> Exchange([FromForm] OboPayload oboPayload)
        {
            // TODO validate request body data and AAD token
            // var validate = oboPayload;

            // TODO
            // get claims from aad token and re use in OpenIddict token

            // use data and return new access token

            var accessToken = await GenerateJwtTokenAsync(
                "alice@alice.com", "newSubsssssuuuubbb");

            return Ok(new OboSuccessResponse
            {
                ExpiresIn = 60 * 60,
                AccessToken = accessToken,
                Scope = oboPayload.Scope
            });
        }

        private async Task<string> GenerateJwtTokenAsync(string username, string sub)
        {
            var certs = await Startup.GetCertificates(_environment, Configuration);

            SigningCredentials signingCredentials = new X509SigningCredentials(certs.ActiveCertificate);

            var alg = signingCredentials.Algorithm;

            //{
            //  "alg": "RS256",
            //  "kid": "....",
            //  "typ": "at+jwt",
            //}

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                // TODO add claims as required if authorized
                Subject = new ClaimsIdentity(new[] {
                    new Claim("sub", sub),
                    new Claim("username", username) ,
                    new Claim("scope", "dataEventRecords")
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                IssuedAt = DateTime.UtcNow,
                Issuer = "https://localhost:44318/",
                Audience = "rs_dataEventRecordsApi",
                SigningCredentials = signingCredentials,
                TokenType = "at+jwt"
            };

            if (tokenDescriptor.AdditionalHeaderClaims == null)
            {
                tokenDescriptor.AdditionalHeaderClaims = new Dictionary<string, object>();
            }

            if (!tokenDescriptor.AdditionalHeaderClaims.ContainsKey("alg"))
            {
                tokenDescriptor.AdditionalHeaderClaims.Add("alg", alg);
            }



            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
    }

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

    public class OboSuccessResponse
    {
        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = string.Empty;
        [JsonPropertyName("token_type")]
        public string TokenType { get; set; } = "Bearer";
        [JsonPropertyName("issued_token_type")]
        public string IssuedTokenType { get; set; } = "urn:ietf:params:oauth:token-type:access_token";
        [JsonPropertyName("scope")]
        public string Scope { get; set; } = string.Empty;
    }
}
