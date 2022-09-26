﻿using System.Security.Cryptography.X509Certificates;

namespace OnBehalfFlowIntegration
{
    public class CreateAccessTokenPayloadModel
    {
        public string UserName { get; set; } = string.Empty;
        public string Sub { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string Audience { get; set; } = string.Empty;
        public string Scope { get; set; } = string.Empty;
        public X509Certificate2? SigningCredentials { get; set; }
    }
}
