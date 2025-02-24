using System.DirectoryServices.Protocols;
using Haihv.Identity.Ldap.Api.Entities;
using Haihv.Identity.Ldap.Api.Interfaces;
using Haihv.Identity.Ldap.Api.Extensions;
using LanguageExt.Common;
using ZiggyCreatures.Caching.Fusion;
using ILogger = Serilog.ILogger;

namespace Haihv.Identity.Ldap.Api.Services;

/// <summary>
/// Dịch vụ xác thực người dùng thông qua LDAP.
/// </summary>
public interface IAuthenticateLdapService
{
    Task<Result<UserLdap>> Authenticate(string username, string password);
}

/// <summary>
/// Dịch vụ xác thực người dùng thông qua LDAP.
/// </summary>
/// <param name="ldapContext">Ngữ cảnh LDAP.</param>
public sealed class AuthenticateLdapService(ILogger logger, ILdapContext ldapContext, IFusionCache fusionCache) : IAuthenticateLdapService
{
    private const string Key = "UserLdap:";
    private static string CacheKey(string username, string password)
        => Key + string.Join("-", username, password).ComputeHash();

    private static string UserNotFoundKey(string username)
        => $"{Key}NotFound:{username}";
    private readonly TimeSpan _expiration = TimeSpan.FromMinutes(15);

    private readonly UserLdapService _userLdapService = new (ldapContext);
    /// <summary>
    /// Xác thực người dùng với tên đăng nhập và mật khẩu.
    /// </summary>
    /// <param name="username">
    /// Tên người dùng (tên đăng nhập) của người dùng.
    /// </param>
    /// <param name="password">Mật khẩu của người dùng.</param>
    /// <returns>Kết quả xác thực người dùng LDAP.</returns>
    public async Task<Result<UserLdap>> Authenticate(string username, string password)
    {
        username = username.Trim().ToLower();
        var cacheKey = CacheKey(username, password);
        try
        {
            if (cacheKey == Key)
            {
                return await AuthenticateInLdap(username, password);
            }
            return await fusionCache.GetOrSetAsync(cacheKey, await AuthenticateInLdap(username, password), _expiration);
        }
        catch (Exception e)
        {
            logger.Error(e, "Lỗi xác thực người dùng LDAP");
            return new Result<UserLdap>(e);
        }
    }
    
    /// <summary>
    /// Xác thực người dùng với tên đăng nhập và mật khẩu.
    /// </summary>
    /// <param name="username">
    /// Tên người dùng (tên đăng nhập) của người dùng.
    /// </param>
    /// <param name="password">Mật khẩu của người dùng.</param>
    /// <returns>
    /// Kết quả xác thực người dùng LDAP.
    /// </returns>
    private async Task<UserLdap> AuthenticateInLdap(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            throw new Exception("Tài khoản hoặc mật khẩu trống");
        }
        if (await fusionCache.GetOrDefaultAsync<bool?>(UserNotFoundKey(username))?? false)
        {
            var messenger = $"Người dùng không tồn tại [{username}]";
            logger.Warning(messenger);
            throw new Exception(messenger);
        }
        var ldapConnectionInfo = ldapContext.LdapConnectionInfo;
        if (string.IsNullOrWhiteSpace(ldapConnectionInfo.Host) ||
            string.IsNullOrWhiteSpace(ldapConnectionInfo.DomainFullname) ||
            string.IsNullOrWhiteSpace(ldapConnectionInfo.Domain))
        {
            logger.Error("Cấu hình Ldap không hợp lệ {LdapConnectionInfo}", ldapConnectionInfo);
            throw new Exception("Cấu hình Ldap không hợp lệ");
        }
        try
        {
            var userLdap = _userLdapService.GetByPrincipalNameAsync(username).Result;
            if (userLdap is null)
            {
                _ = fusionCache.SetAsync(UserNotFoundKey(username), true, TimeSpan.FromSeconds(30)).AsTask();
                var messenger = $"Người dùng không tồn tại [{username}]";
                logger.Warning(messenger);
                throw new Exception(messenger);
            }
            // Thực hiện xác thực
            ldapContext.Connection.Bind(
                new System.Net.NetworkCredential(userLdap.UserPrincipalName, password)
            );
            return userLdap;
        }
        catch (Exception ex)
        {
            if (ex is not LdapException { ErrorCode: 49 })
            {
                logger.Error(ex, "Lỗi khi kết nối đến LDAP: {LdapInfo}", ldapContext.ToLogInfo());
            }
            throw;
        }
    }
}