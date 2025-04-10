namespace Haihv.Identity.Ldap.Api.Options;

public sealed class JwtTokenOptions
{
    public string SecretKey { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public int ExpiryMinutes { get; set; } = 10;
    public int ExpireRefreshTokenDays { get; set; } = 7;
}