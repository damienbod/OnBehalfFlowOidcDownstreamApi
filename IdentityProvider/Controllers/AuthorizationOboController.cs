﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using OnBehalfFlowIntegration;
using OnBehalfFlowIntegration.Server;
using OpeniddictServer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;
using System.Security.Claims;

namespace IdentityProvider.Controllers
{
    public class AuthorizationOboController : Controller
    {
        private readonly IWebHostEnvironment _environment;
        private readonly IConfiguration _configuration;
        private readonly OboConfiguration _oboConfiguration;
        private readonly ILogger<AuthorizationOboController> _logger;

        public AuthorizationOboController(IConfiguration configuration, 
            IWebHostEnvironment env, IOptions<OboConfiguration> oboConfiguration,
            ILoggerFactory loggerFactory)
        {
            _configuration = configuration;
            _environment = env;
            _oboConfiguration = oboConfiguration.Value;
            _logger = loggerFactory.CreateLogger<AuthorizationOboController>();
        }

        [AllowAnonymous]
        [HttpPost("~/connect/obotoken"), Produces("application/json")]
        public async Task<IActionResult> Exchange([FromForm] OboPayload oboPayload)
        {
            var (Valid, Reason) = ValidateOboRequestPayload.IsValid(oboPayload, _oboConfiguration);

            if(!Valid)
            {
                return UnauthorizedValidationParametersFailed(oboPayload, Reason);
            }

            // get claims from aad token and re use in OpenIddict token
            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                _oboConfiguration.AccessTokenMetadataAddress, 
                new OpenIdConnectConfigurationRetriever());

            var wellKnownEndpoints =  await configurationManager.GetConfigurationAsync();

            var accessTokenValidationResult = ValidateOboRequestPayload.ValidateTokenAndSignature(
                oboPayload.assertion,
                _oboConfiguration,
                wellKnownEndpoints.SigningKeys);
            
            if(!accessTokenValidationResult.Valid)
            {
                return UnauthorizedValidationTokenAndSignatureFailed(oboPayload, accessTokenValidationResult);
            }

            var claimsPrincipal = accessTokenValidationResult.ClaimsPrincipal;

            // validate user is an email
            var name = ValidateOboRequestPayload.GetPreferredUserName(claimsPrincipal);
            var isNameAnEmail = ValidateOboRequestPayload.IsEmailValid(name);
            if(!isNameAnEmail)
            {
                return UnauthorizedValidationPrefferedUserNameFailed();
            }

            // validate user exists
            // check in db

            // use data and return new access token
            var (ActiveCertificate, _) = await Startup.GetCertificates(_environment, _configuration);

            var tokenData = new CreateDelegatedAccessTokenPayloadModel
            {
                Sub = Guid.NewGuid().ToString(),
                ClaimsPrincipal = claimsPrincipal,
                SigningCredentials = ActiveCertificate,
                Scope = _oboConfiguration.ScopeForNewAccessToken,
                Audience = _oboConfiguration.AudienceForNewAccessToken,
                Issuer = _oboConfiguration.IssuerForNewAccessToken,
                OriginalClientId = _oboConfiguration.AccessTokenAudience
            };

            var accessToken = CreateDelegatedAccessTokenPayload.GenerateJwtTokenAsync(tokenData);

            _logger.LogInformation("OBO new access token returned sub {sub}", tokenData.Sub);

            if(IdentityModelEventSource.ShowPII)
            {
                _logger.LogDebug("OBO new access token returned for sub {sub} for user {Username}", tokenData.Sub,
                    ValidateOboRequestPayload.GetPreferredUserName(claimsPrincipal));
            }

            return Ok(new OboSuccessResponse
            {
                ExpiresIn = 60 * 60,
                AccessToken = accessToken,
                Scope = oboPayload.scope
            });
        }

        private IActionResult UnauthorizedValidationPrefferedUserNameFailed()
        {
            var errorResult = new OboErrorResponse
            {
                error = "assertion has incorrect claims",
                error_description = "incorrect email used in preferred user name",
                timestamp = DateTime.UtcNow,
                correlation_id = Guid.NewGuid().ToString(),
                trace_id = Guid.NewGuid().ToString(),
            };

            _logger.LogInformation("{error} {error_description} {correlation_id} {trace_id}",
                errorResult.error,
                errorResult.error_description,
                errorResult.correlation_id,
                errorResult.trace_id);

            return Unauthorized(errorResult);
        }

        private IActionResult UnauthorizedValidationTokenAndSignatureFailed(OboPayload oboPayload, (bool Valid, string Reason, ClaimsPrincipal ClaimsPrincipal) accessTokenValidationResult)
        {
            var errorResult = new OboErrorResponse
            {
                error = "Validation request parameters failed",
                error_description = accessTokenValidationResult.Reason,
                timestamp = DateTime.UtcNow,
                correlation_id = Guid.NewGuid().ToString(),
                trace_id = Guid.NewGuid().ToString(),
            };

            if (IdentityModelEventSource.ShowPII)
            {
                _logger.LogDebug("OBO new access token returned for assertion {assertion}", oboPayload.assertion);
            }

            _logger.LogInformation("{error} {error_description} {correlation_id} {trace_id}",
                errorResult.error,
                errorResult.error_description,
                errorResult.correlation_id,
                errorResult.trace_id);

            return Unauthorized(errorResult);
        }

        private IActionResult UnauthorizedValidationParametersFailed(OboPayload oboPayload, string Reason)
        {
            var errorResult = new OboErrorResponse
            {
                error = "Validation request parameters failed",
                error_description = Reason,
                timestamp = DateTime.UtcNow,
                correlation_id = Guid.NewGuid().ToString(),
                trace_id = Guid.NewGuid().ToString(),
            };

            _logger.LogInformation("{error} {error_description} {correlation_id} {trace_id}",
                errorResult.error,
                errorResult.error_description,
                errorResult.correlation_id,
                errorResult.trace_id);

            if (IdentityModelEventSource.ShowPII)
            {
                _logger.LogDebug("OBO new access token returned for assertion {assertion}", oboPayload.assertion);
            }

            return Unauthorized(errorResult);
        }
    }
}
