using Haihv.Identity.Ldap.Api.Entities;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Haihv.Identity.Ldap.Api.Services;

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

    public static long GetExpiry(this HttpContext context)
        => long.TryParse(context.GetClaimValue(JwtRegisteredClaimNames.Exp), out var exp) ? exp : 0;
    
}