using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Haihv.Identity.Ldap.Api.Entities;
using Haihv.Identity.Ldap.Api.Extensions;
using Haihv.Identity.Ldap.Api.Options;
using Haihv.Identity.Ldap.Api.Settings;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Haihv.Identity.Ldap.Api.Services;

public sealed class TokenProvider(IOptions<JwtTokenOptions> options, HybridCache hybridCache)
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
        var token = tokenHandler.CreateToken(tokenDescriptor);
        if (string.IsNullOrWhiteSpace(token))
            _ = hybridCache.SetAccessTokenAsync(token);
        return token; 
    }

    private string GenerateRefreshToken(string samAccountName)
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
    public async Task<(string? RefreshToken, string? SamAccountName)> VerifyRefreshTokenAsync(string refreshToken)
    {
        var (jti, samAccountName, secret, _) = refreshToken.DecodeToken();
        var key = CacheSettings.SecretCacheKey(samAccountName, jti);
        var cachedSecret = await hybridCache.GetOrCreateAsync(key,
            _ => ValueTask.FromResult<string?>(null)); 
        var result = cachedSecret != null && cachedSecret == secret;
        if (!result) return (null, samAccountName);
        _ = hybridCache.RemoveRefreshTokenAsync(samAccountName, jti);  // Xóa refresh token cũ
        _ = hybridCache.RemoveRefreshTokenAsync([samAccountName, jti]); // Xóa các tag liên quan đến refresh token cũ
        return (await GetAndSetRefreshTokenAsync(samAccountName), samAccountName);
    }
    public Task<string> GetAndSetRefreshTokenAsync(string samAccountName)
    {
        var refreshToken = GenerateRefreshToken(samAccountName);
        _ = hybridCache.SetRefreshTokenAsync(refreshToken);
        return Task.FromResult(refreshToken);
    }
}