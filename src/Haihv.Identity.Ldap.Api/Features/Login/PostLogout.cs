using Carter;
using Haihv.Identity.Ldap.Api.Extensions;
using Haihv.Identity.Ldap.Api.Services;
using MediatR;
using ILogger = Serilog.ILogger;


namespace Haihv.Identity.Ldap.Api.Features.Login;

public static class PostLogout
{
    public record Query(bool All) : IRequest<bool>;
    public class Handler(
        IHttpContextAccessor httpContextAccessor,
        ILogger logger,
        TokenProvider tokenProvider) : IRequestHandler<Query, bool>
    {
        public Task<bool> Handle(Query request, CancellationToken cancellationToken)
        {
            var httpContext = httpContextAccessor.HttpContext
                              ?? throw new InvalidOperationException("HttpContext không khả dụng");
            // Lấy thông tin đăng nhập từ context header Bearer token
            var accessToken =  httpContext.Request.Headers.Authorization.ToString().Replace("Bearer ", "");
            // Lấy refresh token từ cookie
            var refreshToken = httpContext.Request.Cookies["refreshToken"];
            var ipAddr = httpContext.GetIpInfo().IpAddress;
            if (request.All)
            {
                // Xóa tất cả token trong hybrid cache
                tokenProvider.RemoveTokenAsync(refreshToken, true, cancellationToken);
                tokenProvider.RemoveTokenAsync(accessToken, true, cancellationToken);
                logger.Information("Đăng xuất tất cả các thiết bị thành công! {ipAddr} {UserPrincipalName}",
                    ipAddr,
                    httpContext.GetDistinguishedName());
            }
            else
            {
                // Xóa token trong hybrid cache
                tokenProvider.RemoveTokenAsync(accessToken, cancellationToken: cancellationToken);
                tokenProvider.RemoveTokenAsync(refreshToken, cancellationToken: cancellationToken);
                logger.Information("Đăng xuất thành công! {ipAddr} {UserPrincipalName}",
                    ipAddr,
                    httpContext.GetDistinguishedName());
            }
            // Xóa cookie cũ - phải đảm bảo các thuộc tính giống với khi tạo cookie
            httpContext.Response.Cookies.Delete("refreshToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None, // Phải giống với khi tạo cookie
                Path = "/api/", // Phải giống với khi tạo cookie
                IsEssential = true
            });
            return Task.FromResult(true);
        }
    }
    public class Endpoint : ICarterModule
    {
        public void AddRoutes(IEndpointRouteBuilder app)
        {
            app.MapPost("/api/logout/", async (ISender sender, bool all = false) =>
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
                .WithTags("Login");
        }
    }
}