using System.DirectoryServices.Protocols;
using Haihv.Identity.Ldap.Api.Entities;
using Haihv.Identity.Ldap.Api.Interfaces;
using Haihv.Identity.Ldap.Api.Extensions;
using LanguageExt.Common;
using Microsoft.Extensions.Caching.Hybrid;
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
public sealed class AuthenticateLdapService(ILogger logger, 
    HybridCache hybridCache,
    ILdapContext ldapContext,
    IGroupLdapService groupLdapService
    ) : IAuthenticateLdapService
{
    private const string KeyUserLdap = "UserLdap:";
    private static string CacheKey(string username, string password)
        => KeyUserLdap + string.Join("-", username, password).ComputeHash(); // Tạo khóa cache từ username và password

    private static string UserNotFoundKey(string username)
        => $"{KeyUserLdap}NotFound:{username}";
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
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            throw new Exception("Tài khoản hoặc mật khẩu trống");
        }
        var cacheKey = CacheKey(username, password);
        try
        {
            var userLdap = await hybridCache.GetOrCreateAsync(cacheKey,
                _ => ValueTask.FromResult<UserLdap?>(null));
            if (userLdap is not null)
            {
                return userLdap;
            }
            // Thực hiện xác thực
            userLdap = await AuthenticateInLdap(username, password);
            var cacheEntryOptions = new HybridCacheEntryOptions
            {
                Expiration = _expiration,
                LocalCacheExpiration = TimeSpan.FromMinutes(5),
            }; 
            _ = hybridCache.SetAsync(cacheKey, userLdap, cacheEntryOptions, tags:[userLdap.SamAccountName]).AsTask();
            // Lưu Cache thông tin nhóm của người dùng
            _ = groupLdapService.SetCacheAsync(userLdap);
            return userLdap;
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
    /// <param name="cancellationToken">Token hủy bỏ.</param>
    /// <returns>
    /// Kết quả xác thực người dùng LDAP.
    /// </returns>
    private async Task<UserLdap> AuthenticateInLdap(string username, string password, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            throw new Exception("Tài khoản hoặc mật khẩu trống");
        }
        var notFoundKey = UserNotFoundKey(username);
        var notFound = await hybridCache.GetOrCreateAsync(notFoundKey,
            _ => new ValueTask<bool>(false), cancellationToken: cancellationToken);
        if (notFound)
        {
            var messenger = $"Người dùng không tồn tại [{username}]";
            logger.Warning(messenger);
            throw new Exception(messenger);
        }
        _ = hybridCache.RemoveAsync(notFoundKey, cancellationToken).AsTask();
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
                var cacheEntryOptions = new HybridCacheEntryOptions
                {
                    Expiration = TimeSpan.FromSeconds(30),
                    LocalCacheExpiration = TimeSpan.FromSeconds(30),
                }; 
                _ = hybridCache.SetAsync(UserNotFoundKey(username), true, cacheEntryOptions, cancellationToken: cancellationToken).AsTask();
                var messenger = $"Người dùng không tồn tại [{username}]";
                logger.Warning(messenger);
                throw new Exception(messenger);
            }
            // Thực hiện xác thực
            ldapContext.Connection.Bind(
                new System.Net.NetworkCredential(userLdap.UserPrincipalName, password)
            );
            if (string.IsNullOrWhiteSpace(userLdap.DistinguishedName))
                userLdap.DistinguishedName = username;
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