using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Haihv.Identity.Ldap.Api.Entities;
using Haihv.Identity.Ldap.Api.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Haihv.Identity.Ldap.Api.Services;

public sealed class TokenProvider(IOptions<JwtTokenOptions> options)
{
    private readonly JwtTokenOptions _options = options.Value;
    public string GenerateAccessToken(UserLdap user)
    {
        var tokenId = Guid.CreateVersion7().ToString();
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SecretKey))
        {
            KeyId = tokenId
        };
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var tokenHandler = new JsonWebTokenHandler();
        
        var claims = new List<Claim>
        {
            new (JwtRegisteredClaimNames.Jti, tokenId),
            new(JwtRegisteredClaimNames.Sub, user.SamAccountName),
            new (JwtRegisteredClaimNames.Name, user.DisplayName ?? string.Empty),
            new (nameof(user.UserPrincipalName), user.UserPrincipalName),
            new (nameof(user.SamAccountName), user.SamAccountName),
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
    public string GenerateRefreshToken(string samAccountName)
    {
        var tokenHandler = new JsonWebTokenHandler();
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Jti, Guid.CreateVersion7().ToString()),
            new Claim(nameof(UserLdap.SamAccountName), samAccountName),
            new Claim("Secret", Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)))
        };
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddDays(_options.ExpireRefreshTokenDays),
        };
        return tokenHandler.CreateToken(tokenDescriptor);
    }
    
}