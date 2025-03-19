using System.Security.Claims;
using System.Text;
using Haihv.Identity.Ldap.Api.Entities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Haihv.Identity.Ldap.Api.Services;

public sealed class TokenProvider(IOptions<JwtTokenOptions> options)
{
    private readonly JwtTokenOptions _options = options.Value;
    public string GenerateToken(UserLdap user)
    {
        var tokenId = Guid.CreateVersion7().ToString();
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SecretKey))
        {
            KeyId =tokenId
        };
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var tokenHandler = new JsonWebTokenHandler();
        
        var claims = new List<Claim>
        {
            new (JwtRegisteredClaimNames.Jti, tokenId),
            new(JwtRegisteredClaimNames.Sub, user.UserPrincipalName ?? string.Empty),
            new (JwtRegisteredClaimNames.Name, user.UserPrincipalName ?? string.Empty),
            new (nameof(UserLdap.DistinguishedName), user.DistinguishedName),
            new (JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
            new (JwtRegisteredClaimNames.UniqueName, user.Id.ToString()),
            new (JwtRegisteredClaimNames.GivenName, user.DisplayName ?? string.Empty),
            new (JwtRegisteredClaimNames.Typ, "Ldap"),
        };
        
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(_options.ExpiryMinutes),
            Issuer = _options.Issuer,
            Audience  = _options.Audience,
            SigningCredentials = credentials
        };

        return tokenHandler.CreateToken(tokenDescriptor);
    }
}

public sealed class JwtTokenOptions
{
    public string SecretKey { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public int ExpiryMinutes { get; set; } = 10;
    public int ExpireRefreshTokenDays { get; set; } = 7;
}

public static class JwtTokenOptionsExtensions
{
    public static void AddJwtTokenOptions(this IHostApplicationBuilder builder, string sectionName)
    {
        // Add Jwt
        builder.Services.Configure<JwtTokenOptions>(builder.Configuration.GetSection(sectionName));
    }
    public static JwtTokenOptions GetJwtTokenOptions(this IConfiguration configuration, string sectionName)
    {
        var options = new JwtTokenOptions();
        configuration.GetSection("JwtOptions").Bind(options);
        return options;
    }
}

public record User(string UserName, string Password);

public static class ClaimExtensions
{
    private static string? GetClaimValue(this ClaimsPrincipal claimsPrincipal, string claimType)
        => claimsPrincipal.Claims.FirstOrDefault(c => c.Type == claimType)?.Value;
    
    public static string? GetDistinguishedName(this ClaimsPrincipal claimsPrincipal)
        => GetClaimValue(claimsPrincipal, nameof(UserLdap.DistinguishedName));
    public static string GetUserPrincipalName(this ClaimsPrincipal claimsPrincipal)
        => GetClaimValue(claimsPrincipal, nameof(UserLdap.UserPrincipalName)) ?? string.Empty;
}