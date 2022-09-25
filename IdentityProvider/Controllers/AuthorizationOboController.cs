﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace IdentityProvider.Controllers
{
    public class AuthorizationOboController : Controller
    {
        [AllowAnonymous]
        [HttpPost("~/connect/obotoken"), Produces("application/json")]
        public async Task<IActionResult> Exchange([FromForm] OboPayload oboPayload)
        {
            // TODO validate data and token
            // var validate = oboPayload;

            // TODO
            // get claims from aad token

            // use data and return new access token

            var accessToken = await GenerateJwtTokenAsync(
                "alice@alice.com", "newSubsssssuuuubbb");

            return Ok(new AccessTokenItem
            {
                ExpiresIn = DateTime.UtcNow.AddHours(1),
                AccessToken = accessToken
            });
        }

        private async Task<string> GenerateJwtTokenAsync(string username, string sub)
        {
            SigningCredentials signingCredentials = await certApi.GetSigningCredentialsAsync();

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
                    new Claim("username", username) 
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                IssuedAt = DateTime.UtcNow,

                Issuer = "https://localhost:44318/",
                Audience = "rs_dataEventRecordsApi",
                SigningCredentials = signingCredentials,
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
        public string grant_type {get;set;}
        public string client_id { get; set; }
        public string client_secret { get; set; }
        public string assertion { get; set; }
        public string scope { get; set; }
        public string requested_token_use { get; set; }
    }

    public class AccessTokenItem
    {
        public DateTime ExpiresIn { get; set; }
        public string AccessToken { get; set; }
    }
}
