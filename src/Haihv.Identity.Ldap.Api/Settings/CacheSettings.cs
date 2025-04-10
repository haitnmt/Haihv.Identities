using Microsoft.Extensions.Caching.Hybrid;

namespace Haihv.Identity.Ldap.Api.Settings;

public static class CacheSettings
{
    public static string LdapUserKey(string samAccountName) => $"{samAccountName}:LdapUser"; 
    public static string LdapGroupsKey(string samAccountName) => $"{samAccountName}:LdapGroups"; 
    public static readonly TimeSpan UserLdapExpiration = TimeSpan.FromDays(1);
    public static string LogoutTime(string samAccountName) => $"{samAccountName}:LogoutTime";
    
    public static Task ClearLogoutTimeAsync(this HybridCache hybridCache, string samAccountName)
    {
        var key = LogoutTime(samAccountName);
        return hybridCache.RemoveAsync(key).AsTask();
    }
    
}