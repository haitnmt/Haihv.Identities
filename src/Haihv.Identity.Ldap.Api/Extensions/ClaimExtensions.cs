using Haihv.Identity.Ldap.Api.Entities;
using Haihv.Identity.Ldap.Api.Settings;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.IdentityModel.JsonWebTokens;
using ILogger = Serilog.ILogger;

namespace Haihv.Identity.Ldap.Api.Extensions;

public static class ClaimExtensions
{
    private static string? GetClaimValue(this HttpContext context, string claimType)
        => context.User.Claims.FirstOrDefault(c => c.Type == claimType)?.Value;
    
    public static string? GetDistinguishedName(this HttpContext context)
        => GetClaimValue(context, nameof(UserLdap.DistinguishedName));
    public static string GetUserPrincipalName(this HttpContext context)
        => GetClaimValue(context, nameof(UserLdap.UserPrincipalName)) ?? string.Empty;
    
    public static string GetSamAccountName(this HttpContext context) 
        => GetClaimValue(context, nameof(UserLdap.SamAccountName)) ?? string.Empty;
    public static string GetUsername(this HttpContext context)
        => GetClaimValue(context, JwtRegisteredClaimNames.Sub) ?? string.Empty;

    private static long GetExpiry(this HttpContext context)
        => long.TryParse(context.GetClaimValue(JwtRegisteredClaimNames.Exp), out var exp) ? exp : 0;
   
    public static async Task<bool> VerifyToken(this HttpContext httpContext, 
        HybridCache hybridCache, 
        ILogger logger, 
        CancellationToken cancellationToken = default)
    {
        var samAccountName = httpContext.GetSamAccountName();
        var ipAddr = httpContext.GetIpInfo().IpAddress;
        // Kiểm tra thông tin token
        var exp = await hybridCache.GetOrCreateAsync(CacheSettings.LogoutTime(samAccountName),
            _ => new ValueTask<long>(0L),
            cancellationToken: cancellationToken);
        if (exp <= 0 || httpContext.GetExpiry() <= exp)
        {
            logger.Information("Token hợp lệ! {ipAddr} {SamAccountName}", ipAddr, samAccountName);
            return true;
        }
        logger.Warning("Token đã hết hạn! {ipAddr} {SamAccountName}", ipAddr, samAccountName);
        return false;
    }
}