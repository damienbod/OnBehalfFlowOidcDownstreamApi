using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.Resource;

namespace ApiAzureAuth.Controllers
{
    [Authorize]
    [AuthorizeForScopes(Scopes = new string[] { "api://72286b8d-5010-4632-9cea-e69e565a5517/user_impersonation" })]
    [ApiController]
    [Route("[controller]")]
    public class MyApiController : ControllerBase
    {
        private readonly OboService _apiService;

        public List<MyApiModel>? DataFromApi { get; set; }

        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        public MyApiController(OboService apiService)
        {
            _apiService = apiService;
        }

        [HttpGet]
        public async Task<IEnumerable<MyApiModel>?> Get()
        {
            var scopeRequiredByApi = new string[] { "access_as_user" };
            HttpContext.VerifyUserHasAnyAcceptedScope(scopeRequiredByApi);

            //DataFromApi = await _apiService.GetApiDataAsync();
            var rng = new Random();
            return Enumerable.Range(1, 5).Select(index => new MyApiModel
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = rng.Next(-20, 55),
                Summary = Summaries[rng.Next(Summaries.Length)]
            })
            .ToArray();
        }
    }
}
