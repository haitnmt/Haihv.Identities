using Carter;
using Haihv.Identity.Ldap.Api.Extensions;
using Haihv.Identity.Ldap.Api.Interfaces;
using Haihv.Identity.Ldap.Api.Services;
using Haihv.Identity.Ldap.Api.Settings;
using MediatR;
using Microsoft.Extensions.Caching.Hybrid;
using ILogger = Serilog.ILogger;

namespace Haihv.Identity.Ldap.Api.Features.Login;

public static class PostRefreshToken
{
    public record Query: IRequest<string?>;

    public class Handler(
        IHttpContextAccessor httpContextAccessor,
        ILogger logger,
        HybridCache hybridCache,
        ICheckIpService checkIpService,
        IUserLdapService userLdapService,
        TokenProvider tokenProvider) : IRequestHandler<Query, string?>
    {
        public async Task<string?> Handle(Query request, CancellationToken cancellationToken)
        {
            var httpContext = httpContextAccessor.HttpContext 
                              ?? throw new InvalidOperationException("HttpContext không khả dụng");
            var ipInfo = httpContext.GetIpInfo();
            var (count, exprSecond) = ipInfo.IsPrivate ? (0, 0) : await checkIpService.CheckLockAsync(ipInfo.IpAddress);
            if (exprSecond > 0)
            {
                logger.Warning("{ClientIp} đang bị khóa do cung cấp thông tin không chính xác!", ipInfo.IpAddress);
                throw new Exception($"Bạn đã nhập sai quá nhiều lần! Vui lòng thử lại sau {exprSecond} giây.");
            }
            // Lấy refresh token từ cookie
            var refreshToken = httpContext.Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(refreshToken))
            {
                logger.Error("Không tìm thấy refresh token trong cookie của client: {ClientIp}", ipInfo.IpAddress);
                throw new UnauthorizedAccessException();
            }
            (refreshToken, var samAccountName) = await tokenProvider.VerifyRefreshTokenAsync(refreshToken);
            if (string.IsNullOrWhiteSpace(refreshToken) || string.IsNullOrWhiteSpace(samAccountName))
            {
                logger.Error("Thông tin không hợp lệ: {ClientIp}", ipInfo.IpAddress);
                const string errorMessage = "Thông tin không hợp lệ";
                if (ipInfo.IsPrivate)
                {
                    throw new Exception(errorMessage);
                }
                _ = checkIpService.SetLockAsync(ipInfo.IpAddress);
                throw new Exception($"{errorMessage} {(count < 3 ? $"Bạn còn {3 - count} lần thử" : "")}");
            }

            var cacheKey = CacheSettings.LdapUserKey(samAccountName);
            var cacheEntryOptions = new HybridCacheEntryOptions
            {
                Expiration = CacheSettings.UserLdapExpiration,
                LocalCacheExpiration = TimeSpan.FromMinutes(5),
            }; 
            List<string> tags = [samAccountName];
            var userLdap = await hybridCache.GetOrCreateAsync(cacheKey, 
                async _ =>
                {
                    var userLdap = await userLdapService.GetBySamAccountNameAsync(samAccountName);
                    if (userLdap == null) return null;
                    tags.Add(userLdap.UserPrincipalName);
                    return await userLdapService.GetBySamAccountNameAsync(samAccountName);
                }, cacheEntryOptions, tags, cancellationToken: cancellationToken);
            if (userLdap == null)
            {
                logger.Error("Không tìm thấy người dùng với SamAccountName: {SamAccountName}", samAccountName);
                const string errorMessage = "Tài khoản không tồn tại";
                if (ipInfo.IsPrivate)
                {
                    throw new Exception(errorMessage);
                }
                _ = checkIpService.SetLockAsync(ipInfo.IpAddress);
                throw new Exception($"{errorMessage} {(count < 3 ? $"Bạn còn {3 - count} lần thử" : "")}");
            }
            var accessToken = tokenProvider.GenerateAccessToken(userLdap);
            // Xóa cookie cũ
            httpContext.Response.Cookies.Delete("refreshToken");
            // Ghi cookie mới
            httpContext.Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None, // Thay đổi từ Strict sang None để hoạt động với CORS
                Path = "/api/",
                IsEssential = true,
                Expires = refreshToken.GetExpiryToken()
            });
            return accessToken;
        }
    }
    public class Endpoint : ICarterModule
    {
        public void AddRoutes(IEndpointRouteBuilder app)
        {
            app.MapPost("/api/refreshToken", async (ISender sender) =>
            {
                try
                {
                    var response = await sender.Send(new Query());
                    return string.IsNullOrWhiteSpace(response) ? 
                        Results.NotFound() : 
                        Results.Ok(response);
                }
                catch (Exception e)
                {
                    return e is UnauthorizedAccessException ? 
                        Results.Unauthorized() : 
                        Results.BadRequest(e.Message);
                }

            }).WithTags("Login");
        }
    }
}