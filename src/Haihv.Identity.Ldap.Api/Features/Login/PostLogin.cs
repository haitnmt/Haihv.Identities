using System.Diagnostics;
using Carter;
using Haihv.Identity.Ldap.Api.Extensions;
using Haihv.Identity.Ldap.Api.Services;
using MediatR;
using Microsoft.Extensions.Caching.Hybrid;
using ILogger = Serilog.ILogger;

namespace Haihv.Identity.Ldap.Api.Features.Login;

public static class Login
{
    public record Command(string Username, string Password, bool RememberMe) : IRequest<Response>;
    
    public record Response(string AccessToken, string? RefreshToken);
    
    public class Handler(IHttpContextAccessor httpContextAccessor, 
        ILogger logger,
        HybridCache hybridCache,
        ICheckIpService checkIpService,
        IAuthenticateLdapService authenticateLdapService, 
        TokenProvider tokenProvider) : IRequestHandler<Command, Response>
    {
        public async Task<Response> Handle(Command request, CancellationToken cancellationToken)
        {
            var httpContext = httpContextAccessor.HttpContext 
                ?? throw new InvalidOperationException("HttpContext không khả dụng");
            var ipInfo = httpContext.GetIpInfo();
            var username = request.Username.Trim().ToLower();
            var (count, exprSecond) = ipInfo.IsPrivate ? (0, 0) : await checkIpService.CheckLockAsync(ipInfo.IpAddress);
            if (exprSecond > 0)
            {
                logger.Warning("{username} đã đăng nhập sai quá nhiều, Ip: {ip}", username, ipInfo.IpAddress);
                throw new Exception($"Bạn đã đăng nhập sai quá nhiều, thử lại sau {exprSecond} giây!");
            }
            var sw = Stopwatch.StartNew();
            const string errorMessage = "Thông tin đăng nhập không chính xác!";
            
            var userResult = await authenticateLdapService.Authenticate(username, request.Password, cancellationToken);

            return userResult.Match<Response>(userLdap =>
                {
                    long elapsed;

                    var samAccountName = userLdap.SamAccountName;
                    // Tạo token
                    var accessToken = tokenProvider.GenerateAccessToken(userLdap);
                    // Xóa thời gian đăng xuất
                    _ = hybridCache.ClearLogoutTimeAsync(samAccountName);
                    // Xoá lock IP
                    if (!ipInfo.IsPrivate)
                        _ = checkIpService.ClearLockAsync(ipInfo.IpAddress);
                    if (!request.RememberMe)
                    {
                        sw.Stop();
                        elapsed = sw.ElapsedMilliseconds;
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

                        return new Response(accessToken, null);
                    }

                    // Tạo refresh token
                    var refreshToken = hybridCache.GetAndSetRefreshTokenAsync(tokenProvider, samAccountName).Result;
                    sw.Stop();
                    elapsed = sw.ElapsedMilliseconds;
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

                    return new Response(accessToken, refreshToken); 
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
                        throw new Exception(errorMessage);
                    }

                    checkIpService.SetLockAsync(ipInfo.IpAddress);
                    throw new Exception($"{errorMessage} {(count < 3 ? $"Bạn còn {3 - count} lần thử" : "")}");
                }
            );
        }
    }
    
    public class Endpoint : ICarterModule
    {
        public void AddRoutes(IEndpointRouteBuilder app)
        {
            app.MapPost("/api/login", async (ISender sender, Command command) =>
                {
                    try
                    {
                        var response = await sender.Send(command);
                        return Results.Ok(response);
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