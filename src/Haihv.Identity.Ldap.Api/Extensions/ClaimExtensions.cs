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
    
}