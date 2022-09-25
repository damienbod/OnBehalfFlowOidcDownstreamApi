using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AzureAdWebApi.Controllers;

[Authorize(AuthenticationSchemes = Consts.MY_AAD_SCHEME, Policy = Consts.MY_AAD_POLICY)]
[Route("api/[controller]")]
public class ValuesController : Controller
{
    [HttpGet]
    public IEnumerable<string> Get()
    {
        // TODO call downstream API using obo

        return new string[] { "data 1 from the api", "data 2 from the api" };
    }
}
