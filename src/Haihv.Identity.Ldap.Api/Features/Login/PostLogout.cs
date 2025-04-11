using Carter;
using Haihv.Identity.Ldap.Api.Extensions;
using Haihv.Identity.Ldap.Api.Settings;
using MediatR;
using Microsoft.Extensions.Caching.Hybrid;
using ILogger = Serilog.ILogger;


namespace Haihv.Identity.Ldap.Api.Features.Login;

public static class PostLogout
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
            app.MapPost("/api/logout/", async (HttpContext httpContext, ISender sender, bool all) =>
                {
                    try
                    {
                        var response = await sender.Send(new Query(all));
                        // Xóa cookie cũ
                        httpContext.Response.Cookies.Delete("refreshToken");
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