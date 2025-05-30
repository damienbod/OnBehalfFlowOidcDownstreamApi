using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using RazorPageMicrosoftEntraIDAuth;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddTransient<EntraIDMyApiService>();
builder.Services.AddHttpClient();

builder.Services.AddOptions();

string[]? initialScopes = builder.Configuration.GetValue<string>("MyApi:ScopeForAccessToken")?.Split(' ');

builder.Services.AddDistributedMemoryCache();
builder.Services.AddMicrosoftIdentityWebAppAuthentication(builder.Configuration, "AzureAd", subscribeToOpenIdConnectMiddlewareDiagnosticsEvents: true)
    .EnableTokenAcquisitionToCallDownstreamApi(initialScopes)
    .AddDistributedTokenCaches();

builder.Services
    .AddAuthorization(options =>
    {
        options.FallbackPolicy = options.DefaultPolicy;
    });

builder.Services.AddRazorPages()
    .AddMvcOptions(options =>
    {
        var policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .Build();
        options.Filters.Add(new AuthorizeFilter(policy));
    }).AddMicrosoftIdentityUI();

builder.Services.AddServerSideBlazor()
    .AddMicrosoftIdentityConsentHandler();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

app.Run();
