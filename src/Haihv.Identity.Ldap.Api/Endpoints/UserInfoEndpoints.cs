using Haihv.Identity.Ldap.Api.Extensions;
using Haihv.Identity.Ldap.Api.Interfaces;
using Haihv.Identity.Ldap.Api.Services;
using Microsoft.Extensions.Caching.Hybrid;
using ILogger = Serilog.ILogger;

namespace Haihv.Identity.Ldap.Api.Endpoints;

public static class UserEndpoints
{
    public static void MapUserEndpoints(this WebApplication app)
    {
        var mapGroup = app.MapGroup("/user");
        mapGroup.MapGet("/groups", GetGroups)
            .RequireAuthorization();
        mapGroup.MapGet("/checkGroup", GetCheckGroup)
            .RequireAuthorization();
    }

    private static async Task<IResult> GetCheckGroup(
        HttpContext context, ILogger logger, IGroupLdapService groupLdapService, HybridCache hybridCache)
    {
        var groupName = context.Request.Query["groupName"].ToString();
        var clearCache = context.Request.Query["clearCache"].ToString() == "true";
        if (!await context.VerifyToken(logger, hybridCache))
        {
            return Results.Unauthorized();
        }
        if (string.IsNullOrWhiteSpace(groupName))
        {
            return Results.BadRequest("Tên nhóm không được để trống!");
        }
        var dn = context.GetDistinguishedName();
        var userPrincipalName = context.GetUserPrincipalName();
        var samAccountName = context.GetSamAccountName();
        var ipAddr = context.GetIpInfo().IpAddress;
        if (string.IsNullOrWhiteSpace(dn))
        {
            logger.Warning("Không tìm thấy thông tin người dùng! {ipAddr} {UserPrincipalName}", ipAddr, userPrincipalName);
            return Results.BadRequest("Không tìm thấy thông tin người dùng!");
        }
        var key = groupLdapService.GetCacheKey(dn);
        try
        {
            if (clearCache)
            {
                await hybridCache.RemoveAsync(key);
            }
            var groups = await hybridCache.GetOrCreateAsync(key, 
                async token => await groupLdapService.GetAllGroupNameByDnAsync(dn, token),
                tags: [samAccountName]
            );
            return groups.Contains(groupName) ? Results.Ok(true) : Results.BadRequest(groupName);
        }
        catch (Exception exception)
        {
            logger.Error(exception, "Lỗi khi kiểm tra nhóm của người dùng {ipAddr} {UserPrincipalName}",
                ipAddr, userPrincipalName);
            return Results.BadRequest("Lỗi khi kiểm tra nhóm của người dùng");
        }
    }


    private static async Task<IResult> GetGroups(
        HttpContext context, ILogger logger, IGroupLdapService groupLdapService, HybridCache hybridCache)
    {

        if (!await context.VerifyToken(logger, hybridCache))
        {
            return Results.Unauthorized();
        }
        var dn = context.GetDistinguishedName();
        var userPrincipalName = context.GetUserPrincipalName();
        var samAccountName = context.GetSamAccountName();
        var ipAddr = context.GetIpInfo().IpAddress;
        if (string.IsNullOrWhiteSpace(dn))
        {
            logger.Warning("Không tìm thấy thông tin người dùng {ipAddr} {UserPrincipalName}", ipAddr, userPrincipalName);
            return Results.BadRequest("Không tìm thấy thông tin người dùng!");
        }

        var key = groupLdapService.GetCacheKey(dn);
        try
        {
            var clearCache = context.Request.Query["clearCache"].ToString() == "true";
            if (clearCache)
            {
                await hybridCache.RemoveAsync(key);
            }
            var groups = await hybridCache.GetOrCreateAsync(key,
                async token => await groupLdapService.GetAllGroupNameByDnAsync(dn, token), 
                tags: [samAccountName]
            );
            return Results.Ok(groups);
        }
        catch (Exception e)
        {
            logger.Error(e, "Lỗi khi lấy thông tin nhóm {ipAddr} {UserPrincipalName}",
                ipAddr, userPrincipalName);
            return Results.BadRequest("Lỗi khi lấy thông tin nhóm");
        }
    }

}