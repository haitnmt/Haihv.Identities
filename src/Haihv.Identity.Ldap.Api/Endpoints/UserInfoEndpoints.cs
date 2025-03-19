using Haihv.Identity.Ldap.Api.Extensions;
using Haihv.Identity.Ldap.Api.Interfaces;
using Haihv.Identity.Ldap.Api.Services;
using Microsoft.AspNetCore.Mvc;
using ZiggyCreatures.Caching.Fusion;
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

    public static string GetCacheKey(string dn) => $"UserGroups{dn}";
    private static async Task<IResult> GetCheckGroup(
        HttpContext context, ILogger logger, IGroupLdapService groupLdapService, IFusionCache fusionCache,
        [FromQuery] string? groupName = null, [FromQuery] bool clearCache = false)
    {
        if (string.IsNullOrWhiteSpace(groupName))
        {
            return Results.BadRequest("Tên nhóm không được để trống!");
        }
        var dn = context.User.GetDistinguishedName();
        var user = context.User.GetUserPrincipalName();
        var ipAddr = context.GetIpInfo().IpAddress;
        if (string.IsNullOrWhiteSpace(dn))
        {
            logger.Warning("Không tìm thấy thông tin người dùng! {ipAddr} {UserPrincipalName}", ipAddr, user);
            return Results.BadRequest("Không tìm thấy thông tin người dùng!");
        }
        var key = GetCacheKey(dn);
        try
        {
            if (clearCache)
            {
                await fusionCache.RemoveAsync(key);
            }
            var groups = await fusionCache.GetOrSetAsync(key, token =>
                groupLdapService.GetAllGroupNameByDnAsync(dn, token)
            );
            return groups.Contains(groupName) ? Results.Ok(true) : Results.BadRequest(groupName);
        }
        catch (Exception exception)
        {
            logger.Error(exception, "Lỗi khi kiểm tra nhóm của người dùng {ipAddr} {UserPrincipalName}", 
                ipAddr, user);
            return Results.BadRequest("Lỗi khi kiểm tra nhóm của người dùng");
        }
    }
    
    
    private static async Task<IResult> GetGroups(
        HttpContext context, ILogger logger, IGroupLdapService groupLdapService, IFusionCache fusionCache,
        [FromQuery] bool clearCache = false)
    {
        var dn = context.User.GetDistinguishedName();
        var user = context.User.GetUserPrincipalName();
        var ipAddr = context.GetIpInfo().IpAddress;
        if (string.IsNullOrWhiteSpace(dn))
        {
            logger.Warning("Không tìm thấy thông tin người dùng {ipAddr} {UserPrincipalName}", ipAddr, user);
            return Results.BadRequest("Không tìm thấy thông tin người dùng!");
        }

        var key = GetCacheKey(dn);
        try
        {
            if (clearCache)
            {
                await fusionCache.RemoveAsync(key);
            }
            var groups = await fusionCache.GetOrSetAsync(key, token =>
                groupLdapService.GetAllGroupNameByDnAsync(dn, token)
            );
            return Results.Ok(groups);
        }
        catch (Exception e)
        {
            logger.Error(e, "Lỗi khi lấy thông tin nhóm {ipAddr} {UserPrincipalName}", 
                ipAddr, user);
            return Results.BadRequest("Lỗi khi lấy thông tin nhóm");
        }
    }
    
}