using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace AzureAdWebApi;

public class Startup
{
    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAuthentication(options =>
        {
            options.DefaultScheme = "UNKNOWN";
            options.DefaultChallengeScheme = "UNKNOWN";

        })
        .AddJwtBearer(Consts.MY_AAD_SCHEME, jwtOptions =>
        {
            jwtOptions.MetadataAddress = Configuration["AzureAd:MetadataAddress"];
            jwtOptions.Authority = Configuration["AzureAd:Authority"];
            jwtOptions.Audience = Configuration["AzureAd:Audience"];
            jwtOptions.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidAudiences = Configuration.GetSection("ValidAudiences").Get<string[]>(),
                ValidIssuers = Configuration.GetSection("ValidIssuers").Get<string[]>()
            };
        });


        services.AddSingleton<IAuthorizationHandler, AadApiHandler>();

        services.AddAuthorization(options =>
        {
            options.AddPolicy(Consts.MY_AAD_POLICY, policyAllRequirement =>
            {
                policyAllRequirement.Requirements.Add(new ApiAadRequirement());
            });
        });

        services.AddControllers();
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        IdentityModelEventSource.ShowPII = true;
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

        app.UseStaticFiles();
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers().RequireAuthorization();
        });
    }
}
