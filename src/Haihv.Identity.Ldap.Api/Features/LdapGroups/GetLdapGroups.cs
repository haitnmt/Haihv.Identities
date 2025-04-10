using Carter;
using Haihv.Identity.Ldap.Api.Extensions;
using Haihv.Identity.Ldap.Api.Interfaces;
using Haihv.Identity.Ldap.Api.Settings;
using MediatR;
using Microsoft.Extensions.Caching.Hybrid;
using ILogger = Serilog.ILogger;

namespace Haihv.Identity.Ldap.Api.Features.LdapGroups;

public static class GetLdapGroups
{
    public record Query(bool ClearCache = false) : IRequest<List<string>>;
    public class Handler(
        IHttpContextAccessor httpContextAccessor,
        ILogger logger,
        HybridCache hybridCache,
        IGroupLdapService groupLdapService) : IRequestHandler<Query, List<string>>
    {

        public async Task<List<string>> Handle(Query request, CancellationToken cancellationToken)
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
                if (request.ClearCache)
                {
                    await hybridCache.RemoveAsync(key, cancellationToken);
                }
                var groups = await hybridCache.GetOrCreateAsync(key, 
                    async token => await groupLdapService.GetAllGroupNameByDnAsync(dn, token), 
                    tags: [samAccountName], 
                    cancellationToken: cancellationToken);
                return groups;
            }
            catch (Exception ex)
            {
                logger.Error(ex,":Lỗi khi lấy danh sách nhóm LDAP cho người dùng {samAccountName}", 
                    samAccountName);
                throw;
            }
        }
        public class Endpoint : ICarterModule
        {
            public void AddRoutes(IEndpointRouteBuilder app)
            {
                app.MapGet("/api/ldapGroup", async (ISender sender, bool clearCache = false) =>
                    {
                        try
                        {
                            var response = await sender.Send(new Query(clearCache));
                            return response.Count > 0 ? Results.Ok(response) : Results.NoContent();
                        } 
                        catch (Exception e)
                        {
                            return e is UnauthorizedAccessException ? 
                                Results.Unauthorized() : 
                                Results.Problem(detail:e.Message);
                        }
                    })
                    .WithTags("LdapGroups")
                    .RequireAuthorization();
            }
        }
    }
}