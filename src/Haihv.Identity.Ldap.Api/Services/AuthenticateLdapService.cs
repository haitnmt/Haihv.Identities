using System.DirectoryServices.Protocols;
using Haihv.Identity.Ldap.Api.Entities;
using Haihv.Identity.Ldap.Api.Exceptions;
using Haihv.Identity.Ldap.Api.Interfaces;
using Haihv.Identity.Ldap.Api.Settings;
using LanguageExt.Common;
using Microsoft.Extensions.Caching.Hybrid;
using ILogger = Serilog.ILogger;

namespace Haihv.Identity.Ldap.Api.Services;

/// <summary>
/// Dịch vụ xác thực người dùng thông qua LDAP.
/// </summary>
public interface IAuthenticateLdapService
{
    Task<Result<UserLdap>> Authenticate(string username, string password, CancellationToken cancellationToken = default);
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
    private static string UserNotFoundKey(string username)
        => $"NotFound:{username}";

    private readonly UserLdapService _userLdapService = new (ldapContext);
    /// <summary>
    /// Xác thực người dùng với tên đăng nhập và mật khẩu.
    /// </summary>
    /// <param name="username">
    /// Tên người dùng (tên đăng nhập) của người dùng.
    /// </param>
    /// <param name="password">Mật khẩu của người dùng.</param>
    /// <param name="cancellationToken">Token hủy bỏ.</param>
    /// <returns>Kết quả xác thực người dùng LDAP.</returns>
    public async Task<Result<UserLdap>> Authenticate(string username, string password, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            return new Result<UserLdap>(new InvalidCredentialsException(0, new ArgumentException("Tài khoản hoặc mật khẩu trống")));
        }

        try
        {   
            var cacheEntryOptions = new HybridCacheEntryOptions
            {
                Expiration = CacheSettings.UserLdapExpiration,
                LocalCacheExpiration = TimeSpan.FromMinutes(5),
            }; 
            var userLdap = await AuthenticateInLdap(username, password, cancellationToken);
            var cacheKey = CacheSettings.LdapUserKey(username);
            List<string> tags = [userLdap.SamAccountName, userLdap.UserPrincipalName];
            // Lưu Cache thông tin người dùng
            _ = hybridCache.SetAsync(cacheKey, userLdap, cacheEntryOptions, tags, cancellationToken).AsTask();
            // Lưu Cache thông tin nhóm của người dùng
            _ = groupLdapService.SetCacheAsync(userLdap, cancellationToken);
            return userLdap;
        }
        catch (Exception e)
        {
            logger.Error(e, "Lỗi xác thực người dùng LDAP");
            
            // Chuyển đổi các exception thông thường thành LdapApiException
            var apiException = e switch
            {
                UserNotFoundException => e,
                LdapApiException => e,
                LdapException { ErrorCode: 49 } ldapEx => new InvalidCredentialsException(0, ldapEx),
                LdapException => new LdapConfigurationException("Lỗi kết nối đến máy chủ LDAP", e),
                _ => new AuthenticationException("Lỗi xác thực người dùng LDAP", e)
            };
            
            return new Result<UserLdap>(apiException);
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
            throw new InvalidCredentialsException(0, new ArgumentException("Tài khoản hoặc mật khẩu trống"));
        }
        var notFoundKey = UserNotFoundKey(username);
        var notFound = await hybridCache.GetOrCreateAsync(notFoundKey,
            _ => new ValueTask<bool>(false), cancellationToken: cancellationToken);
        if (notFound)
        {
            logger.Warning("Người dùng không tồn tại [{Username}]", username);
            throw new UserNotFoundException(username);
        }
        await hybridCache.RemoveAsync(notFoundKey, cancellationToken);
        var ldapConnectionInfo = ldapContext.LdapConnectionInfo;
        if (string.IsNullOrWhiteSpace(ldapConnectionInfo.Host) ||
            string.IsNullOrWhiteSpace(ldapConnectionInfo.DomainFullname) ||
            string.IsNullOrWhiteSpace(ldapConnectionInfo.Domain))
        {
            logger.Error("Cấu hình Ldap không hợp lệ {LdapConnectionInfo}", ldapConnectionInfo);
            throw new LdapConfigurationException("Cấu hình Ldap không hợp lệ");
        }
        try
        {
            var userLdap = _userLdapService.GetByPrincipalNameAsync(username).Result;
            if (userLdap is null)
            {
                var cacheEntryOptions = new HybridCacheEntryOptions
                {
                    Expiration = TimeSpan.FromSeconds(300),
                    LocalCacheExpiration = TimeSpan.FromSeconds(30),
                }; 
                _ = hybridCache.SetAsync(UserNotFoundKey(username), true, cacheEntryOptions, cancellationToken: cancellationToken).AsTask();
                logger.Warning("Người dùng không tồn tại [{Username}]", username);
                throw new UserNotFoundException(username);
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
            if (ex is LdapApiException)
            {
                throw; // Truyền tiếp các exception đã được xử lý
            }

            if (ex is not LdapException ldapEx) throw new AuthenticationException("Lỗi xác thực người dùng LDAP", ex);
            if (ldapEx.ErrorCode == 49)
            {
                // Mã lỗi 49 là lỗi xác thực (sai mật khẩu)
                throw new InvalidCredentialsException(0, ldapEx);
            }
                
            logger.Error(ex, "Lỗi khi kết nối đến LDAP: {LdapInfo}", ldapContext.ToLogInfo());
            throw new LdapConfigurationException("Lỗi kết nối đến máy chủ LDAP", ex);

            // Các lỗi khác
        }
    }
}