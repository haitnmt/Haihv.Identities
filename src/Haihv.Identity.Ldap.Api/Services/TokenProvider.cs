using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Haihv.Identity.Ldap.Api.Entities;
using Haihv.Identity.Ldap.Api.Exceptions;
using Haihv.Identity.Ldap.Api.Options;
using Haihv.Identity.Ldap.Api.Settings;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Haihv.Identity.Ldap.Api.Services;

public sealed class TokenProvider(HybridCache hybridCache, IOptions<JwtTokenOptions> options)
{
    private readonly JwtTokenOptions _options = options.Value;

    private static (string Jti, string SamAccountName, string Secret, bool IsExpired) DecodeRefreshToken(string refreshToken)
    {

        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(refreshToken);

        var jti = GetClaimValue(JwtRegisteredClaimNames.Jti);
        var samAccountName = GetClaimValue(nameof(UserLdap.SamAccountName));
        var secret = GetClaimValue("Secret");

        return (jti, samAccountName, secret, jwt.ValidTo <= DateTime.UtcNow);

        string GetClaimValue(string claimType)
        {
            if (!jwt.TryGetClaim(claimType, out var claim))
                throw new InvalidTokenException($"Token không hợp lệ: thiếu claim {claimType}");
            return claim.Value;
        }
    }
    
    private static (string Jti, string SamAccountName, bool IsExpired) DecodeToken(string token)
    {
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(token);

        var jti = GetClaimValue(JwtRegisteredClaimNames.Jti);
        var samAccountName = GetClaimValue(nameof(UserLdap.SamAccountName));

        return (jti, samAccountName, jwt.ValidTo <= DateTime.UtcNow);

        string GetClaimValue(string claimType)
        {
            if (!jwt.TryGetClaim(claimType, out var claim))
                throw new InvalidTokenException($"Token không hợp lệ: thiếu claim {claimType}");
            return claim.Value;
        }
    }
    
    public async Task<string> GenerateAccessToken(UserLdap user)
    {
        var jti = Guid.CreateVersion7().ToString();
        var samAccountName = user.SamAccountName;
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SecretKey))
        {
            KeyId = jti
        };
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var tokenHandler = new JsonWebTokenHandler();
        
        var claims = new List<Claim>
        {
            new (JwtRegisteredClaimNames.Jti, jti),
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
        var key = CacheSettings.AccessTokenKey(samAccountName, jti);
        var cacheEntryOptions = new HybridCacheEntryOptions
        {
            Expiration = TimeSpan.FromMinutes(_options.ExpiryMinutes),
            LocalCacheExpiration = TimeSpan.FromSeconds(30)
        }; 
        var token = tokenHandler.CreateToken(tokenDescriptor);
        // Lưu vào hybrid cache để kiểm tra khi verify access token
        await hybridCache.SetAsync(key, true, cacheEntryOptions, [samAccountName, jti]);
        return token; 
    }
    
    public async Task<string> GenerateRefreshToken(string samAccountName)
    {
        var tokenHandler = new JsonWebTokenHandler();
        var jti = Guid.CreateVersion7().ToString();
        var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Jti, jti),
            new Claim(nameof(UserLdap.SamAccountName), samAccountName),
            new Claim("Secret", secret)
        };
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddDays(_options.ExpireRefreshTokenDays),
        };

        var key = CacheSettings.RefreshTokenKey(samAccountName, jti);
        var cacheEntryOptions = new HybridCacheEntryOptions
        {
            Expiration = TimeSpan.FromDays(_options.ExpireRefreshTokenDays),
            LocalCacheExpiration = TimeSpan.FromHours(1)
        }; 
        await hybridCache.SetAsync(key, secret, cacheEntryOptions, [samAccountName, jti]);
        return tokenHandler.CreateToken(tokenDescriptor);
    }
    
    private async Task RemoveTokenByJtiAsync(string jti, CancellationToken cancellationToken = default)
    {
        await hybridCache.RemoveByTagAsync(jti, cancellationToken);
    } 
    
    public async Task<(bool IsExpired, string? RefreshToken, string? SamAccountName)> VerifyRefreshTokenAsync(string refreshToken)
    {
        // Giải nén thông tin từ refresh token
        var (jti, samAccountName, secret, isExpired) = DecodeRefreshToken(refreshToken);
        
        // Kiểm tra xem refresh token có còn hiệu lực hay không
        if (isExpired) return (true, null, samAccountName);
        
        // Kiểm tra xem refresh token có còn tồn tại trong hybrid cache không
        var key = CacheSettings.RefreshTokenKey(samAccountName, jti);
        var cachedSecret = await hybridCache.GetOrCreateAsync(key,
            _ => ValueTask.FromResult<string?>(null)); 
        
        // Kiểm tra xem refresh token có còn hợp lệ hay không
        var result = cachedSecret != null && cachedSecret == secret;
        if (!result) return (isExpired, null, samAccountName);
        _ = RemoveTokenByJtiAsync(jti);  // Xóa refresh token cũ
        return (isExpired, await GenerateRefreshToken(samAccountName), samAccountName);
    }
    
    public async Task<bool> VerifyAccessToken(string? accessToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(accessToken)) return false;
        var (jti, samAccountName, isExpired) = DecodeToken(accessToken);
        if (isExpired) return false;

        // Kiểm tra xem token có tồn tại trong hybrid cache không
        var key = CacheSettings.AccessTokenKey(samAccountName,jti);
        
        return await hybridCache.GetOrCreateAsync(key,
            _ => new ValueTask<bool>(false),
            cancellationToken: cancellationToken);
        
    }
    public async Task RemoveTokenAsync(string? token, bool all = false, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token)) 
            return;
        var (jti, samAccountName, _) = DecodeToken(token);
        List<string> tags = all ? [samAccountName, jti] : [jti];
        await hybridCache.RemoveByTagAsync(tags, cancellationToken).AsTask();
    }
}

public static class TokenExtensions
{
    public static DateTimeOffset GetExpiryToken(this string refreshToken)
    {
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(refreshToken);
        return jwt.ValidTo;
    }
}