using Carter;
using Haihv.Identity.Ldap.Api.Exceptions;
using Haihv.Identity.Ldap.Api.Extensions;
using Haihv.Identity.Ldap.Api.Interfaces;
using Haihv.Identity.Ldap.Api.Services;
using Haihv.Identity.Ldap.Api.Settings;
using MediatR;
using Microsoft.Extensions.Caching.Hybrid;
using ILogger = Serilog.ILogger;

namespace Haihv.Identity.Ldap.Api.Features.LdapGroups;

public static class GetCheckLdapGroup
{
    public record Query(string GroupName, bool ClearCache = false) : IRequest<bool>;
    public class Handler(
        IHttpContextAccessor httpContextAccessor,
        ILogger logger,
        HybridCache hybridCache,
        TokenProvider tokenProvider,
        IGroupLdapService groupLdapService) : IRequestHandler<Query, bool>
    {

        public async Task<bool> Handle(Query request, CancellationToken cancellationToken)
        {
            var httpContext = httpContextAccessor.HttpContext
                              ?? throw new InvalidOperationException("HttpContext không khả dụng");
            // Lấy thông tin đăng nhập từ context header Bearer token
            var accessToken =  httpContext.Request.Headers.Authorization.ToString().Replace("Bearer ", "");
            // Kiểm tra AccessToken có hợp lệ hay không?
            if (!await tokenProvider.VerifyAccessToken(accessToken, cancellationToken))
                throw new InvalidTokenException("Token không hợp lệ");
            var dn = httpContext.GetDistinguishedName();
            var userPrincipalName = httpContext.GetUserPrincipalName();
            var samAccountName = httpContext.GetSamAccountName();
            var ipAddr = httpContext.GetIpInfo().IpAddress;
            if (string.IsNullOrWhiteSpace(dn))
            {
                logger.Warning("Không tìm thấy thông tin người dùng! {ipAddr} {UserPrincipalName}", ipAddr, userPrincipalName);
                throw new UserNotFoundException(userPrincipalName ?? "unknown");
            }
            var key = CacheSettings.LdapGroupsKey(samAccountName);
            try
            {
                if (request.ClearCache)
                {
                    await hybridCache.RemoveAsync(key, cancellationToken);
                }
                var groups = await hybridCache.GetOrCreateAsync(key, 
                    async token => await groupLdapService.GetAllGroupNameByDnAsync(dn, token), 
                    tags: [samAccountName], 
                    cancellationToken: cancellationToken);
                return groups.Contains(request.GroupName);
            }
            catch(Exception ex){
                logger.Error(ex,"Lỗi khi kiểm tra nhóm LDAP {samAccountName} {groupName}", 
                    samAccountName,request.GroupName);
                
                // Chuyển đổi exception thành LdapApiException
                if (ex is LdapApiException)
                {
                    throw; // Truyền tiếp các exception đã được xử lý
                }
                
                throw new LdapConfigurationException($"Lỗi khi kiểm tra nhóm LDAP {request.GroupName} cho người dùng {samAccountName}", ex);
            }
        }
        public class Endpoint : ICarterModule
        {
            public void AddRoutes(IEndpointRouteBuilder app)
            {
                app.MapGet("/api/ldapGroup/check", async (ISender sender, string groupName, bool clearCache = false) =>
                    {
                        // Không cần try-catch ở đây vì đã có middleware xử lý exception toàn cục
                        var response = await sender.Send(new Query(groupName, clearCache));
                        return response ? Results.Ok(true) : Results.NoContent();
                    })
                    .WithTags("LdapGroups")
                    .RequireAuthorization();
            }
        }
    }
}