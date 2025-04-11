using Haihv.Identity.Ldap.Api.Entities;
using Haihv.Identity.Ldap.Api.Services;
using Haihv.Identity.Ldap.Api.Settings;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Haihv.Identity.Ldap.Api.Extensions;

public static class TokenExtensions
{
    public static (string Jti, string SamAccountName, string Secret, TimeSpan Expiry) DecodeToken(this string refreshToken)
    {
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(refreshToken);

        var jti = GetClaimValue(JwtRegisteredClaimNames.Jti);
        var samAccountName = GetClaimValue(nameof(UserLdap.SamAccountName));
        var secret = GetClaimValue("Secret");
        var expiry = GetClaimValue(JwtRegisteredClaimNames.Exp);

        if (!long.TryParse(expiry, out var expiryLong))
            throw new InvalidOperationException($"Invalid refresh token: {refreshToken}");

        // Chuyển đổi Unix timestamp (giây) thành DateTime
        var expiryDateTime = DateTimeOffset.FromUnixTimeSeconds(expiryLong).DateTime;
        
        // Tính thời gian còn lại
        var remainingTime = expiryDateTime - DateTime.UtcNow;

        return (jti, samAccountName, secret, remainingTime);

        string GetClaimValue(string claimType)
        {
            if (!jwt.TryGetClaim(claimType, out var claim))
                throw new InvalidOperationException($"Invalid refresh token: {refreshToken}");
            return claim.Value;
        }
    }
    
    public static DateTimeOffset GetExpiryToken(this string refreshToken)
    {
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(refreshToken);
        return jwt.ValidTo;
    }

    public static async Task SetRefreshTokenAsync(this HybridCache hybridCache, string refreshToken)
    {
        var (jti, samAccountName, secret, expiry) = refreshToken.DecodeToken();
        var key = CacheSettings.SecretCacheKey(samAccountName, jti);
        var cacheEntryOptions = new HybridCacheEntryOptions
        {
            Expiration = expiry,
            LocalCacheExpiration = TimeSpan.FromHours(1)
        }; 
        var tags = new[] { samAccountName, jti, secret.GetHashCode().ToString() };
        await hybridCache.SetAsync(key, secret, cacheEntryOptions, tags);
    }
    
    public static async Task SetAccessTokenAsync(this HybridCache hybridCache, string accessToken)
    {
        var (jti, samAccountName, _, expiry) = accessToken.DecodeToken();
        var key = CacheSettings.AccessTokenCacheKey(samAccountName);
        var cacheEntryOptions = new HybridCacheEntryOptions
        {
            Expiration = expiry,
            LocalCacheExpiration = TimeSpan.FromSeconds(30)
        }; 
        var tags = new[] { samAccountName, jti };
        await hybridCache.SetAsync(key, jti, cacheEntryOptions, tags);
    }
    
    public static async Task RemoveRefreshTokenAsync(this HybridCache hybridCache, string samAccountName, string jti)
    {
        var key = CacheSettings.SecretCacheKey(samAccountName, jti);
        await hybridCache.RemoveAsync(key);
    } 

    public static async Task RemoveRefreshTokenAsync(this HybridCache hybridCache, string[] tags)
    {
        await hybridCache.RemoveByTagAsync(tags);
    }

}