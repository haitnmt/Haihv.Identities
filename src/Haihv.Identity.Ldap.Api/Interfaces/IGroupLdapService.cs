using Haihv.Identity.Ldap.Api.Entities;

namespace Haihv.Identity.Ldap.Api.Interfaces;

public interface IGroupLdapService
{
    /// <summary>
    /// Lấy danh sách tất cả (có đệ quy) tên nhóm theo distinguishedName.
    /// </summary>
    /// <param name="distinguishedName">
    /// Distinguished Name (DN) của nhóm hoặc người dùng để tìm các nhóm của chúng.
    /// </param>
    /// <param name="cancellationToken">
    /// CancellationToken.
    /// </param>
    /// <returns>
    /// Danh sách tên nhóm.
    /// </returns>
    Task<List<string>> GetAllGroupNameByDnAsync(string distinguishedName, CancellationToken cancellationToken = default);
    
}