using Haihv.Identity.Ldap.Api.Entities;

namespace Haihv.Identity.Ldap.Api.Interfaces;

public interface IUserLdapService
{
    /// <summary>
    /// Lấy thông tin người dùng từ LDAP.
    /// </summary>
    /// <param name="username">Tên người dùng cần lấy thông tin.</param>
    /// <param name="whenChanged"></param>
    /// <returns>Đối tượng UserLdap chứa thông tin người dùng.</returns>
    Task<UserLdap?> GetByPrincipalNameAsync(string username, DateTime whenChanged = default);

    /// <summary>
    /// Lấy thông tin người dùng từ LDAP.
    /// </summary>
    /// <param name="samAccountName">
    /// Tên đăng nhập của người dùng (sAMAccountName) trong Active Directory.
    /// </param>
    /// <param name="whenChanged"></param>
    /// <returns>Đối tượng UserLdap chứa thông tin người dùng.</returns>
    Task<UserLdap?> GetBySamAccountNameAsync(string samAccountName, DateTime whenChanged = default);
    
}