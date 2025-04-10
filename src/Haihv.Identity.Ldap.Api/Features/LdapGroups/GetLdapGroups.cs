using Carter;
using Haihv.Identity.Ldap.Api.Extensions;
using Haihv.Identity.Ldap.Api.Interfaces;
using Haihv.Identity.Ldap.Api.Settings;
using MediatR;
using Microsoft.Extensions.Caching.Hybrid;
using ILogger = Serilog.ILogger;

namespace Haihv.Identity.Ldap.Api.Features.LdapGroups;

public static class GetLdapGroup
{
    public record Query(string GroupName) : IRequest<bool>;
    public class Handler(
        IHttpContextAccessor httpContextAccessor,
        ILogger logger,
        HybridCache hybridCache,
        IGroupLdapService groupLdapService) : IRequestHandler<Query, bool>
    {

        public async Task<bool> Handle(Query request, CancellationToken cancellationToken)
        {
            var httpContext = httpContextAccessor.HttpContext
                              ?? throw new InvalidOperationException("HttpContext không khả dụng");
            if (!await httpContext.VerifyToken(hybridCache, logger, cancellationToken: cancellationToken))
            {
                throw new UnauthorizedAccessException();
            }
            var dn = httpContext.GetDistinguishedName();
            var userPrincipalName = httpContext.GetUserPrincipalName();
            var samAccountName = httpContext.GetSamAccountName();
            var ipAddr = httpContext.GetIpInfo().IpAddress;
            if (string.IsNullOrWhiteSpace(dn))
            {
                logger.Warning("Không tìm thấy thông tin người dùng! {ipAddr} {UserPrincipalName}", ipAddr, userPrincipalName);
                throw new NullReferenceException("Không tìm thấy DN của người dùng!");
            }
            var key = CacheSettings.LdapGroupsKey(samAccountName);
            try
            {
                var clearCache = httpContext.Request.Query["clearCache"].ToString().Equals("true", StringComparison.CurrentCultureIgnoreCase);
                if (clearCache)
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
                logger.Error(ex,"{userPrincipalName} {dn} {groupName}", userPrincipalName,dn,request.GroupName);
                throw;
            }
        }
        public class Endpoint : ICarterModule
        {
            public void AddRoutes(IEndpointRouteBuilder app)
            {
                app.MapGet("/api/ldapGroup/check", async (ISender sender, string groupName) =>
                    {
                        try
                        {
                            var response = await sender.Send(new Query(groupName));
                            return response ? Results.Ok("Token hợp lệ!") : Results.Unauthorized();
                        } 
                        catch (Exception e)
                        {
                            return Results.BadRequest(e.Message);
                        }
                    })
                    .WithTags("LdapGroups")
                    .RequireAuthorization();
            }
        }
    }
}