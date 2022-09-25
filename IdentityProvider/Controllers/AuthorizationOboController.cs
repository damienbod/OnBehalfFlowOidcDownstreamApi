using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityProvider.Controllers
{
    public class AuthorizationOboController : Controller
    {
        [AllowAnonymous]
        [HttpPost("~/connect/obotoken"), Produces("application/json")]
        public async Task<IActionResult> Exchange([FromForm] OboPayload oboPayload)
        {
            var data = oboPayload;
            return Ok();
        }
    }

    public class OboPayload
    {
        public string grant_type {get;set;}
        public string client_id { get; set; }
        public string client_secret { get; set; }
        public string assertion { get; set; }
        public string scope { get; set; }
        public string requested_token_use { get; set; }
    }
}
