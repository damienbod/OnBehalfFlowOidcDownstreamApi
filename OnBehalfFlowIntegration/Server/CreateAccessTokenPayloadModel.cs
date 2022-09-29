using System.Security.Cryptography.X509Certificates;

namespace OnBehalfFlowIntegration.Server;

public class CreateDelegatedAccessTokenPayloadModel
{
    public string UserName { get; set; } = string.Empty;
    public string Azpacr { get; set; } = string.Empty;
    public string Azp { get; set; } = string.Empty;
    public string Sub { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
    public X509Certificate2? SigningCredentials { get; set; }
}
