using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using OnBehalfFlowIntegration;
using OnBehalfFlowIntegration.Server;
using OpeniddictServer;
using Microsoft.Extensions.Options;

namespace IdentityProvider.Controllers
{
    public class AuthorizationOboController : Controller
    {
        private readonly IWebHostEnvironment _environment;
        private readonly IConfiguration _configuration;
        private readonly OboConfiguration _oboConfiguration;

        public AuthorizationOboController(IConfiguration configuration, 
            IWebHostEnvironment env, IOptions<OboConfiguration> oboConfiguration)
        {
            _configuration = configuration;
            _environment = env;
            _oboConfiguration = oboConfiguration.Value;
        }

        [AllowAnonymous]
        [HttpPost("~/connect/obotoken"), Produces("application/json")]
        public async Task<IActionResult> Exchange([FromForm] OboPayload oboPayload)
        {
            var (Valid, Reason) = ValidateOboRequestPayload.IsValid(oboPayload, _oboConfiguration);

            if(!Valid)
            {
                return Unauthorized(Reason);
            }

            // get claims from aad token and re use in OpenIddict token
            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                _oboConfiguration.AccessTokenMetadataAddress, 
                new OpenIdConnectConfigurationRetriever());

            var wellKnownEndpoints =  await configurationManager.GetConfigurationAsync();

            var accessTokenValidationResult = ValidateOboRequestPayload.ValidateTokenSignature(
                oboPayload.assertion,
                _oboConfiguration,
                wellKnownEndpoints.SigningKeys);
            
            if(!accessTokenValidationResult.Valid)
            {
                return Unauthorized(accessTokenValidationResult.Reason);
            }

            var claimsPrincipal = accessTokenValidationResult.ClaimsPrincipal;

            // use data and return new access token
            var (ActiveCertificate, _) = await Startup.GetCertificates(_environment, _configuration);

            var accessToken = CreateDelegatedAccessTokenPayload.GenerateJwtTokenAsync(
                new CreateDelegatedAccessTokenPayloadModel
                {
                    Sub = Guid.NewGuid().ToString(),
                    UserName = ValidateOboRequestPayload.GetPreferredUserName(claimsPrincipal),
                    Azp = ValidateOboRequestPayload.GetAzp(claimsPrincipal),
                    Azpacr = ValidateOboRequestPayload.GetAzpacr(claimsPrincipal),
                    SigningCredentials = ActiveCertificate,
                    Scope = _oboConfiguration.ScopeForNewAccessToken,
                    Audience = _oboConfiguration.AudienceForNewAccessToken,
                    Issuer = "https://localhost:44318/",
                });

            return Ok(new OboSuccessResponse
            {
                ExpiresIn = 60 * 60,
                AccessToken = accessToken,
                Scope = oboPayload.scope
            });
        }
    }
}
