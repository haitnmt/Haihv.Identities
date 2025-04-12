using System.Diagnostics;
using Carter;
using Haihv.Identity.Ldap.Api.Exceptions;
using Haihv.Identity.Ldap.Api.Extensions;
using Haihv.Identity.Ldap.Api.Services;
using MediatR;
using Microsoft.Extensions.Caching.Hybrid;
using ILogger = Serilog.ILogger;

namespace Haihv.Identity.Ldap.Api.Features.Login;

public static class PostLogin
{
    public record Command(string Username, string Password, bool RememberMe) : IRequest<string?>;
    
    public class Handler(IHttpContextAccessor httpContextAccessor, 
        ILogger logger,
        HybridCache hybridCache,
        ICheckIpService checkIpService,
        IAuthenticateLdapService authenticateLdapService, 
        TokenProvider tokenProvider) : IRequestHandler<Command, string?>
    {
        public async Task<string?> Handle(Command request, CancellationToken cancellationToken)
        {
            var httpContext = httpContextAccessor.HttpContext 
                ?? throw new InvalidOperationException("HttpContext không khả dụng");
            var ipInfo = httpContext.GetIpInfo();
            var username = request.Username.Trim().ToLower();
            var (count, exprSecond) = ipInfo.IsPrivate ? (0, 0) : await checkIpService.CheckLockAsync(ipInfo.IpAddress);
            if (exprSecond > 0)
            {
                logger.Warning("{username} đã đăng nhập sai quá nhiều, Ip: {ip}", username, ipInfo.IpAddress);
                throw new IpLockedException(exprSecond);
            }
            var sw = Stopwatch.StartNew();
            const string errorMessage = "Thông tin đăng nhập không chính xác!";
            
            var userResult = await authenticateLdapService.Authenticate(username, request.Password, cancellationToken);

            return userResult.Match<string?>(userLdap =>
                {
                    var samAccountName = userLdap.SamAccountName;
                    // Tạo token
                    var accessToken = tokenProvider.GenerateAccessToken(userLdap);
                    // Xoá lock IP
                    if (!ipInfo.IsPrivate)
                        _ = checkIpService.ClearLockAsync(ipInfo.IpAddress);
                    string? refreshToken = null;
                    if (request.RememberMe)
                    {
                        // Tạo refresh token
                        refreshToken = tokenProvider.GenerateRefreshToken(samAccountName);
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
                    }
                    
                    sw.Stop();
                    var elapsed = sw.ElapsedMilliseconds;
                    if (elapsed > 1000)
                    {
                        logger.Warning("Đăng nhập thành công: [{Elapsed} ms] {Username} {ClientIp}",
                            elapsed,
                            samAccountName,
                            ipInfo);
                    }
                    else
                    {
                        logger.Information("Đăng nhập thành công: [{Elapsed} ms] {Username} {ClientIp}",
                            elapsed,
                            samAccountName,
                            ipInfo);
                    }

                    return accessToken; 
                },
                ex =>
                {
                    sw.Stop();
                    var elapsed = sw.ElapsedMilliseconds;
                    logger.Error(ex, "Đăng nhập thất bại: [{Elapsed} ms] {Username} {ClientIp}",
                        elapsed,
                        username,
                        ipInfo);
                    if (ipInfo.IsPrivate)
                    {
                        throw new InvalidCredentialsException(0, ex);
                    }

                    checkIpService.SetLockAsync(ipInfo.IpAddress);
                    throw new InvalidCredentialsException(3 - count, ex);
                }
            );
        }
    }
    
    public class Endpoint : ICarterModule
    {
        public void AddRoutes(IEndpointRouteBuilder app)
        {
            app.MapPost("/api/login", async (HttpContext httpContext, ISender sender, Command command) =>
                {
                    // Không cần try-catch ở đây vì đã có middleware xử lý exception toàn cục
                    var response = await sender.Send(command);
                    return string.IsNullOrWhiteSpace(response) ? 
                        Results.Unauthorized() :
                        Results.Ok(response);
                })
                .WithTags("Login");
        }
    }
}