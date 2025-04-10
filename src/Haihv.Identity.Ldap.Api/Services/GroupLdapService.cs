using System.DirectoryServices.Protocols;
using Haihv.Identity.Ldap.Api.Entities;
using Haihv.Identity.Ldap.Api.Enum;
using Haihv.Identity.Ldap.Api.Extensions;
using Haihv.Identity.Ldap.Api.Interfaces;
using Haihv.Identity.Ldap.Api.Settings;
using Microsoft.Extensions.Caching.Hybrid;

namespace Haihv.Identity.Ldap.Api.Services;

public sealed class GroupLdapService(HybridCache hybridCache, ILdapContext ldapContext) : IGroupLdapService
{
    /// <summary> 
    /// Distinguished Name (DN) của nhóm gốc LDAP.
    /// </summary>
    public string RootGroupDn => _ldapConnectionInfo.RootGroupDn;
    
    private readonly LdapConnectionInfo _ldapConnectionInfo = ldapContext.LdapConnectionInfo;

    private readonly AttributeTypeLdap[] _attributesToReturns =
    [
        AttributeTypeLdap.ObjectGuid,
        AttributeTypeLdap.DistinguishedName,
        AttributeTypeLdap.SamAccountName,
        AttributeTypeLdap.Cn,
        AttributeTypeLdap.MemberOf,
        AttributeTypeLdap.Member,
        AttributeTypeLdap.WhenCreated,
        AttributeTypeLdap.WhenChanged
    ];

    /// <summary>
    /// Kiểm tra sự tồn tại của nhóm LDAP dựa trên Distinguished Name (DN).
    /// </summary>
    /// <param name="distinguishedName">DN của nhóm cần kiểm tra.</param>
    /// <returns>True nếu nhóm tồn tại, ngược lại là False.</returns>
    private async Task<bool> ExistsAsync(string distinguishedName)
    {
        try
        {
            AttributeWithValueCollectionLdap attributeWithValueCollection = new(ObjectClassTypeLdap.Group);
            attributeWithValueCollection.Add(AttributeTypeLdap.DistinguishedName, [distinguishedName]);
            ResultEntryCollectionLdap resultEntryCollection = new(ldapContext);
            var entryCollection =
                await resultEntryCollection.GetAsync(attributeWithValueCollection, [AttributeTypeLdap.ObjectGuid]);
            return entryCollection is not null && entryCollection.Count != 0;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// Kiểm tra sự tồn tại của nhóm LDAP dựa trên Object GUID.
    /// </summary>
    /// <param name="objectGuid">Object GUID của nhóm cần kiểm tra.</param>
    /// <returns>True nếu nhóm tồn tại, ngược lại là False.</returns>
    public async Task<bool> ExistsAsync(Guid objectGuid)
    {
        try
        {
            AttributeWithValueCollectionLdap attributeWithValueCollection = new(ObjectClassTypeLdap.Group);
            attributeWithValueCollection.Add(AttributeTypeLdap.ObjectGuid, [objectGuid]);
            ResultEntryCollectionLdap resultEntryCollectionLdap = new(ldapContext);
            var entryCollection =
                await resultEntryCollectionLdap.GetAsync(attributeWithValueCollection, [AttributeTypeLdap.ObjectGuid]);
            return entryCollection is not null && entryCollection.Count != 0;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// Chuyển đổi kết quả tìm kiếm LDAP thành danh sách các đối tượng GroupLdap.
    /// </summary>
    /// <param name="resultEntries">Danh sách kết quả tìm kiếm LDAP.</param>
    /// <returns>Danh sách các đối tượng GroupLdap.</returns>
    private async Task<List<GroupLdap>> GetByResultEntryCollectionAsync(
        SearchResultEntryCollection? resultEntries)
    {
        List<GroupLdap> result = [];
        if (resultEntries is null || resultEntries.Count <= 0) return result;
        foreach (SearchResultEntry entry in resultEntries)
        {
            // Lấy giá trị thuộc tính WhenCreated và chuyển đổi thành DateTimeOffset
            var whenCreatedString = entry.Attributes[AttributeLdap.GetAttribute(AttributeTypeLdap.WhenCreated)]?[0]
                .ToString();
            if (!DateTimeOffset.TryParseExact(whenCreatedString, "yyyyMMddHHmmss.0Z", null,
                    System.Globalization.DateTimeStyles.AssumeUniversal, out var whenCreated))
            {
                whenCreated = DateTimeOffset.MinValue;
            }

            // Lấy giá trị thuộc tính WhenChanged và chuyển đổi thành DateTimeOffset
            var whenChangedString = entry.Attributes[AttributeLdap.GetAttribute(AttributeTypeLdap.WhenChanged)]?[0]
                .ToString();
            if (!DateTimeOffset.TryParseExact(whenChangedString, "yyyyMMddHHmmss.0Z", null,
                    System.Globalization.DateTimeStyles.AssumeUniversal, out var whenChanged))
            {
                whenChanged = DateTimeOffset.MinValue;
            }

            // Tạo đối tượng GroupLdap từ các thuộc tính của entry
            GroupLdap groupsLdap = new()
            {
                Id = new Guid((byte[])entry.Attributes[AttributeLdap.GetAttribute(AttributeTypeLdap.ObjectGuid)][0]),
                DistinguishedName =
                    entry.Attributes[AttributeLdap.GetAttribute(AttributeTypeLdap.DistinguishedName)][0].ToString() ??
                    string.Empty,
                SamAccountName =
                    entry.Attributes[AttributeLdap.GetAttribute(AttributeTypeLdap.SamAccountName)][0].ToString() ??
                    string.Empty,
                Cn = entry.Attributes[AttributeLdap.GetAttribute(AttributeTypeLdap.Cn)][0].ToString() ?? string.Empty,
                MemberOf = entry.Attributes[AttributeLdap.GetAttribute(AttributeTypeLdap.MemberOf)]
                    ?.GetValues(typeof(string)).Cast<string>().ToHashSet() ?? [],
                WhenCreated = whenCreated,
                WhenChanged = whenChanged
            };

            HashSet<string> groupMembers = [];
            HashSet<string> userMembers = [];

            foreach (var distinguishedName in entry.Attributes[AttributeLdap.GetAttribute(AttributeTypeLdap.Member)]
                         ?.GetValues(typeof(string)).Cast<string>().ToArray() ?? [])
            {
                if (await ExistsAsync(distinguishedName))
                {
                    groupMembers.Add(distinguishedName);
                }
                else
                {
                    userMembers.Add(distinguishedName);
                }
            }

            // Gán danh sách thành viên cho nhóm
            groupsLdap.GroupMembers = [.. groupMembers];
            groupsLdap.UserMembers = [.. userMembers];
            result.Add(groupsLdap);
        }

        return result;
    }

    /// <summary>
    /// Lấy thông tin nhóm LDAP dựa trên Distinguished Name (DN).
    /// </summary>
    /// <param name="distinguishedName">DN của nhóm cần lấy thông tin.</param>
    /// <param name="whenChanged">
    /// Ngày để lọc các nhóm theo ngày thay đổi cuối cùng của chúng (>=).
    /// Mặc định là <see cref="DateTime.MinValue"/>.
    /// </param>
    /// <returns>Đối tượng <see cref="GroupLdap"/> đại diện cho nhóm LDAP, hoặc null nếu không tìm thấy.</returns>
    public async Task<GroupLdap?> GetByDnAsync(string distinguishedName,
        DateTime whenChanged = default)
    {
        try
        {
            AttributeWithValueCollectionLdap attributeWithValueCollection = new(ObjectClassTypeLdap.Group);
            attributeWithValueCollection.Add(AttributeTypeLdap.DistinguishedName, [distinguishedName]);
            // Thêm điều kiện lọc theo ngày thay đổi cuối cùng của nhóm
            if (whenChanged != default && whenChanged != DateTime.MinValue)
                attributeWithValueCollection.Add(AttributeTypeLdap.WhenChanged,
                    [whenChanged.ToString("yyyyMMddHHmmss.0Z")], OperatorLdap.GreaterThanOrEqual);
            ResultEntryCollectionLdap resultEntryCollectionLdap = new(ldapContext);
            var entryCollection =
                await resultEntryCollectionLdap.GetAsync(attributeWithValueCollection, _attributesToReturns);
            if (entryCollection is null || entryCollection.Count == 0) return null;
            return (await GetByResultEntryCollectionAsync(entryCollection))[0];
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// Lấy thông tin nhóm gốc LDAP.
    /// </summary>
    /// <returns>Đối tượng <see cref="GroupLdap"/> đại diện cho nhóm gốc LDAP, hoặc null nếu không tìm thấy.</returns>
    public async Task<GroupLdap?> GetRootGroupAsync()
    {
        return await GetByDnAsync(_ldapConnectionInfo.RootGroupDn);
    }

    /// <summary>
    /// Lấy tất cả các nhóm LDAP đã thay đổi kể từ ngày chỉ định
    /// <c>(AllMemberOf = "memberOf:1.2.840.113556.1.4.1941:";)</c>
    /// </summary>
    /// <param name="whenChanged">
    /// Ngày để lọc các nhóm theo ngày thay đổi cuối cùng của chúng (>=).
    /// Mặc định là <see cref="DateTime.MinValue"/>.
    /// </param>
    /// <returns>Danh sách các đối tượng <see cref="GroupLdap"/> đại diện cho các nhóm LDAP.</returns>
    public async Task<List<GroupLdap>> GetAllGroupsLdapAsync(DateTime whenChanged = default)
    {
        AttributeWithValueCollectionLdap attributeWithValueCollection = new(ObjectClassTypeLdap.Group);
        attributeWithValueCollection.Add(AttributeTypeLdap.AllMemberOf, [_ldapConnectionInfo.RootGroupDn]);
        if (whenChanged != default && whenChanged != DateTimeOffset.MinValue)
            attributeWithValueCollection.Add(AttributeTypeLdap.WhenChanged,
                [whenChanged.ToString("yyyyMMddHHmmss.0Z")], OperatorLdap.GreaterThanOrEqual);

        ResultEntryCollectionLdap resultEntryCollectionLdap = new(ldapContext);
        var entryCollection =
            await resultEntryCollectionLdap.GetAsync(attributeWithValueCollection, _attributesToReturns);
        return await GetByResultEntryCollectionAsync(entryCollection);
    }

    /// <summary>
    /// Lấy danh sách các Distinguished Name (DN) của các nhóm LDAP dựa trên thuộc tính memberOf.
    /// </summary>
    /// <param name="memberOf">DN của nhóm cha để tìm các nhóm con.</param>
    /// <param name="whenChanged">
    /// Ngày để lọc các nhóm theo ngày thay đổi cuối cùng của chúng (>=).
    /// Mặc định là <see cref="DateTime.MinValue"/>.
    /// </param>
    /// <returns>Danh sách các DN của các nhóm LDAP.</returns>
    public async Task<List<string>> GetDnByMemberOfAsync(string memberOf, DateTime whenChanged = default)
    {
        AttributeWithValueCollectionLdap attributeWithValueCollection = new(ObjectClassTypeLdap.Group);
        attributeWithValueCollection.Add(AttributeTypeLdap.MemberOf, [memberOf]);
        // Thêm điều kiện lọc theo ngày thay đổi cuối cùng của nhóm
        if (whenChanged != default && whenChanged != DateTime.MinValue)
            attributeWithValueCollection.Add(AttributeTypeLdap.WhenChanged,
                [whenChanged.ToString("yyyyMMddHHmmss.0Z")], OperatorLdap.GreaterThanOrEqual);


        ResultEntryCollectionLdap resultEntryCollectionLdap = new(ldapContext);
        var entryCollection =
            await resultEntryCollectionLdap.GetAsync(attributeWithValueCollection,
                [AttributeTypeLdap.DistinguishedName]);
        List<string> result = [];
        return entryCollection == null
            ? result
            : (from SearchResultEntry entry in entryCollection
                select entry.Attributes[AttributeLdap.GetAttribute(AttributeTypeLdap.DistinguishedName)][0].ToString()
                into distinguishedName
                where !string.IsNullOrEmpty(distinguishedName)
                select distinguishedName).ToList();
    }

    /// <summary>
    /// Lấy danh sách các nhóm cha của một nhóm LDAP dựa trên Distinguished Name (DN).
    /// </summary>
    /// <param name="distinguishedName">DN của nhóm cần lấy thông tin.</param>
    /// <returns>Danh sách các DN của các nhóm cha.</returns>
    private async Task<List<string>> GetMemberOfByDnAsync(string distinguishedName)
    {
        AttributeWithValueCollectionLdap attributeWithValueCollection = new(ObjectClassTypeLdap.Group);
        attributeWithValueCollection.Add(AttributeTypeLdap.Member, [distinguishedName]);

        ResultEntryCollectionLdap resultEntryCollectionLdap = new(ldapContext);
        var entryCollection =
            await resultEntryCollectionLdap.GetAsync(attributeWithValueCollection,
                [AttributeTypeLdap.DistinguishedName]);
        return entryCollection == null
            ? []
            : (from SearchResultEntry entry in entryCollection
                select entry.Attributes[AttributeLdap.GetAttribute(AttributeTypeLdap.DistinguishedName)][0].ToString()
                into dn
                where !string.IsNullOrEmpty(dn)
                select dn).ToList();
    }

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
    public async Task<List<string>> GetAllGroupNameByDnAsync(string distinguishedName,
        CancellationToken cancellationToken = default)
    {
        // Danh sách để lưu các nhóm LDAP tìm được
        List<string> groupNames = [];
        Queue<string> dnQueue = new(); // Hàng đợi để duyệt theo tầng
        List<string> groupDns = [];
        dnQueue.Enqueue(distinguishedName);

        while (dnQueue.Count > 0)
        {
            // Lấy nhóm hiện tại từ hàng đợi
            var currentDn = dnQueue.Dequeue();
            // Thêm nhóm vào danh sách kết quả nếu thoả mãn điều kiện
            var currentGroup = await GetByDnAsync(currentDn);
            // Thêm vào danh sách kết quả nếu có nhóm thoả mãn 
            if (!string.IsNullOrWhiteSpace(currentGroup?.Cn) && !groupNames.Contains(currentGroup.Cn))
                groupNames.Add(currentGroup.Cn);

            // Lấy danh sách các DN của nhóm cha
            var dns = await GetMemberOfByDnAsync(currentDn);

            foreach (var dn in dns.Where(dn => !dnQueue.Contains(dn) && !groupDns.Contains(dn)))
            {
                groupDns.Add(dn);
                dnQueue.Enqueue(dn); // Thêm DN của nhóm cha vào hàng đợi
            }
        }

        return groupNames;
    }
    
    public Task SetCacheAsync(UserLdap userLdap, CancellationToken cancellationToken = default)
    {
        // Tao cache cho thông tin người dùng
        var key = CacheSettings.LdapGroupsKey(userLdap.SamAccountName);
        _ = hybridCache.GetOrCreateAsync(key,
            async token => await GetAllGroupNameByDnAsync(userLdap.DistinguishedName, token),
            tags: [userLdap.SamAccountName],
            cancellationToken: cancellationToken).AsTask();
        return Task.CompletedTask;
    }
}