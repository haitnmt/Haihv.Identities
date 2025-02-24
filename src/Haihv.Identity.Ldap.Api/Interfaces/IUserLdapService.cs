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
    /// <param name="distinguishedName">
    /// Tên định danh của người dùng cần lấy thông tin.
    /// </param>
    /// <param name="whenChanged"></param>
    /// <returns>Đối tượng UserLdap chứa thông tin người dùng.</returns>
    Task<UserLdap?> GetByDistinctNameAsync(string distinguishedName, DateTime whenChanged = default);
}