using Microsoft.Extensions.Caching.Hybrid;

namespace Haihv.Identity.Ldap.Api.Settings;

public static class CacheSettings
{
    public static string LdapUserKey(string samAccountName) => $"{samAccountName}:LdapUser"; 
    public static string LdapGroupsKey(string samAccountName) => $"{samAccountName}:LdapGroups"; 
    public static readonly TimeSpan UserLdapExpiration = TimeSpan.FromDays(1);
    public static string RefreshTokenKey(string samAccountName, string jti) => $"{samAccountName}:RefreshToken:{jti}";
    public static string AccessTokenKey(string samAccountName, string jti) => $"{samAccountName}:AccessToken:{jti}";
    
}