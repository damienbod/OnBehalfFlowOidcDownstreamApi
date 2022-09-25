using Microsoft.AspNetCore.Authorization;

namespace AzureAdWebApi;

public class AadApiHandler : AuthorizationHandler<ApiAadRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
        ApiAadRequirement requirement)
    {
        var issuer = string.Empty;
  
        var issClaim = context.User.Claims.FirstOrDefault(c => c.Type == "iss");
        if (issClaim != null)
            issuer = issClaim.Value;

        if (issuer == Consts.MY_AAD_ISS) // AAD
        {
            // "azp": "--your-azp-claim-value--",
            var azpClaim = context.User.Claims.FirstOrDefault(c => c.Type == "azp"
                && c.Value == "46d2f651-813a-4b5c-8a43-63abcb4f692c");
            if (azpClaim != null)
            {
                context.Succeed(requirement);
            }
        }

        return Task.CompletedTask;
    }
}
