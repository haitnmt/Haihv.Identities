using Carter;
using Haihv.Identity.Ldap.Api.Extensions;
using Haihv.Identity.Ldap.Api.Settings;
using MediatR;
using Microsoft.Extensions.Caching.Hybrid;
using ILogger = Serilog.ILogger;


namespace Haihv.Identity.Ldap.Api.Features.Login;

public static class PostGetLogout
{
    public record Query(bool All) : IRequest<bool>;
    public class Handler(
        IHttpContextAccessor httpContextAccessor,
        ILogger logger,
        HybridCache hybridCache) : IRequestHandler<Query, bool>
    {
        public async Task<bool> Handle(Query request, CancellationToken cancellationToken)
        {
            var httpContext = httpContextAccessor.HttpContext
                              ?? throw new InvalidOperationException("HttpContext không khả dụng");
            var samAccountName = httpContext.GetSamAccountName();
            var ipAddr = httpContext.GetIpInfo().IpAddress;
            if (request.All)
            {
                var key = CacheSettings.LogoutTime(samAccountName);
                await hybridCache.SetAsync(key, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), cancellationToken: cancellationToken);
            }
            List<string> tags = [samAccountName, httpContext.GetUsername(), httpContext.GetUserPrincipalName()];
            _ = hybridCache.RemoveByTagAsync(tags.Distinct(), cancellationToken).AsTask();
            logger.Information("Đăng xuất thành công! {ipAddr} {UserPrincipalName}",
                ipAddr,
                httpContext.GetDistinguishedName());
            return true;
        }
    }
    public class Endpoint : ICarterModule
    {
        public void AddRoutes(IEndpointRouteBuilder app)
        {
            app.MapGet("/api/logout/", async (ISender sender, bool all) =>
                {
                    try
                    {
                        var response = await sender.Send(new Query(all));
                        return response ? Results.Ok() : Results.Unauthorized();
                    } 
                    catch (Exception e)
                    {
                        return Results.BadRequest(e.Message);
                    }
                })
                .WithTags("Login")
                .RequireAuthorization();
        }
    }
}