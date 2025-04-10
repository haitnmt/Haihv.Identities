using Haihv.Identity.Ldap.Api.Entities;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Haihv.Identity.Ldap.Api.Services;

public static class RefreshTokenExtensions
{
    private static (string Jti, string SamAccountName, string Secret, TimeSpan Expiry) DecodeRefreshToken(this string refreshToken)
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
    private static string SecretCacheKey(string samAccountName, string jti) => $"{samAccountName}:{jti}:Secret";
    public static async Task SetRefreshTokenAsync(this HybridCache hybridCache, string refreshToken)
    {

        var (jti, samAccountName, secret, expiry) = refreshToken.DecodeRefreshToken();
        var key = SecretCacheKey(samAccountName, jti);
        var cacheEntryOptions = new HybridCacheEntryOptions
        {
            Expiration = expiry,
            LocalCacheExpiration = TimeSpan.FromHours(1)
        }; 
        var tags = new[] { samAccountName, jti, secret.GetHashCode().ToString() };
        await hybridCache.SetAsync(key, secret, cacheEntryOptions, tags);
    }
    public static async Task RemoveRefreshTokenAsync(this HybridCache hybridCache, string refreshToken)
    {
        var (jti, samAccountName, _, _) = refreshToken.DecodeRefreshToken();
        var key = SecretCacheKey(samAccountName, jti);
        await hybridCache.RemoveAsync(key);
    }

    public static async Task RemoveRefreshTokenAsync(this HybridCache hybridCache, string[] tags)
    {
        await hybridCache.RemoveByTagAsync(tags);
    }
}