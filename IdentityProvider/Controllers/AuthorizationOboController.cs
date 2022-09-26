using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OnBehalfFlowIntegration;
using OpeniddictServer;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

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

            var (ActiveCertificate, _) = await Startup.GetCertificates(_environment, Configuration);

            var accessToken = CreateAccessTokenPayload.GenerateJwtTokenAsync(
                new CreateAccessTokenPayloadModel
                {
                    Sub = "newSubsssssuuuubbb",
                    UserName = "alice@alice.com",
                    SigningCredentials = ActiveCertificate,
                    Scope = "dataEventRecords",
                    Audience = "rs_dataEventRecordsApi",
                    Issuer = "https://localhost:44318/",
                });

            return Ok(new OboSuccessResponse
            {
                ExpiresIn = 60 * 60,
                AccessToken = accessToken,
                Scope = oboPayload.Scope
            });
        }
    }
}
