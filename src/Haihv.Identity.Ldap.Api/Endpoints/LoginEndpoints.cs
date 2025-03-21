using System.Diagnostics;
using Haihv.Identity.Ldap.Api.Interfaces;
using Haihv.Identity.Ldap.Api.Models;
using Haihv.Identity.Ldap.Api.Services;
using Haihv.Identity.Ldap.Api.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using ZiggyCreatures.Caching.Fusion;
using ILogger = Serilog.ILogger;
using LoginRequest = Haihv.Identity.Ldap.Api.Models.LoginRequest;

namespace Haihv.Identity.Ldap.Api.Endpoints;

public static class LoginEndpoints
{
    public static void MapLoginEndpoints(this WebApplication app)
    {
        app.MapPost("/login", Login);
        app.MapPost("/logout", Logout)
            .RequireAuthorization();
        app.MapPost("/logoutAll", LogoutAll)
            .RequireAuthorization();
        app.MapGet("/verify", Verify)
            .RequireAuthorization();
    }

    private static string GetCacheKeyLogoutTime(string username) => $"LogoutTime:{username}";
    public static async Task<bool> VerifyToken(this HttpContext context, ILogger logger, IFusionCache fusionCache)
    {
        var userPrincipalName = context.GetUserPrincipalName();
        var ipAddr = context.GetIpInfo().IpAddress;
        // Kiểm tra thông tin token
        var exp = await fusionCache.GetOrDefaultAsync(GetCacheKeyLogoutTime(userPrincipalName), 0L);
        if (exp <= 0 || context.GetExpiry() <= exp) return true;
        logger.Warning("Token đã hết hạn! {ipAddr} {UserPrincipalName}", ipAddr, userPrincipalName);
        return false;
    }
    private static async Task<IResult> Verify(HttpContext context, ILogger logger, IFusionCache fusionCache)
     => await context.VerifyToken(logger, fusionCache) ? Results.Ok() : Results.Unauthorized();
    
    private static async Task<IResult> Logout(HttpContext context, ILogger logger, IFusionCache fusionCache, 
        [FromQuery] bool all = false)
    {
        var userPrincipalName = context.GetUserPrincipalName();
        var ipAddr = context.GetIpInfo().IpAddress;
        if (string.IsNullOrWhiteSpace(userPrincipalName))
        {
            logger.Warning("Không tìm thấy thông tin người dùng! {ipAddr}", ipAddr);
            return Results.BadRequest("Không tìm thấy thông tin người dùng!");
        }

        if (all)
        {
            var key = GetCacheKeyLogoutTime(userPrincipalName);
            await fusionCache.SetAsync(key, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        }
        _ = fusionCache.RemoveByTagAsync(userPrincipalName).AsTask();
        _ = fusionCache.RemoveByTagAsync(context.GetUsername()).AsTask();
        _ = fusionCache.RemoveByTagAsync(context.GetSamAccountName()).AsTask();
        logger.Information("Đăng xuất thành công! {ipAddr} {UserPrincipalName}", 
            ipAddr, 
            context.GetDistinguishedName());
        return Results.Ok();
    }
    private static async Task<IResult> LogoutAll(HttpContext context, ILogger logger, IFusionCache fusionCache)
     => await Logout(context, logger, fusionCache, true);
    private record LoginResponse(string Token, Guid TokenId, string RefreshToken, DateTime Expiry);

    private static async Task<IResult> Login([FromBody] LoginRequest request,
        ILogger logger,
        IAuthenticateLdapService authenticateLdapService,
        IGroupLdapService groupLdapService,
        TokenProvider tokenProvider,
        IRefreshTokensService refreshTokensService,
        ICheckIpService checkIpService,
        IOptions<JwtTokenOptions> options,
        IFusionCache fusionCache,
        HttpContext httpContext)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
        {
            return Results.BadRequest(new Response<LoginResponse>("Tên đăng nhập và mật khẩu không được để trống!"));
        }

        var ipInfo = httpContext.GetIpInfo();
        var (count, exprSecond) = ipInfo.IsPrivate ? (0, 0) : await checkIpService.CheckLockAsync(ipInfo.IpAddress);
        if (exprSecond > 0)
        {
            return Results.BadRequest(
                new Response<LoginResponse>($"Bạn đã đăng nhập sai quá nhiều, thử lại sau {exprSecond} giây!"));
        }

        const string errorMessage = "Thông tin đăng nhập không chính xác!";
        var sw = Stopwatch.StartNew();
        request.Username = request.Username.Trim().ToLower();
        // Xác thực trong cơ sở dữ liệu trước:
        var result = await authenticateLdapService.Authenticate(request.Username, request.Password);

        return await result.Match<Task<IResult>>(async userLdap =>
            {
                if (userLdap is null)
                {
                    sw.Stop();
                    var elapsed = sw.ElapsedMilliseconds;
                    logger.Warning("Đăng nhập thất bại: [{Elapsed} ms] {Username} {ClientIp}",
                        elapsed,
                        request.Username,
                        ipInfo);
                    if (ipInfo.IsPrivate)
                    {
                        return Results.BadRequest(new Response<LoginResponse>(errorMessage));
                    }
                    await checkIpService.SetLockAsync(ipInfo.IpAddress);
                    return Results.BadRequest(
                        new Response<LoginResponse>(
                            $"{errorMessage} {(count < 3 ? $"Bạn còn {3 - count} lần thử" : "")}"));
                }
                // Tạo token
                var accessToken = tokenProvider.GenerateToken(userLdap, request.Username);
                
                // Tạo refresh token
                var tokenId = Guid.CreateVersion7();
                var resultRefreshToken = await refreshTokensService.VerifyOrCreateAsync(tokenId, userLdap.SamAccountName);
                var expiry = DateTime.UtcNow.AddMinutes(options.Value.ExpiryMinutes);
                return resultRefreshToken.Match<IResult>(
                    refreshToken =>
                    {
                        // Xóa thời gian đăng xuất
                        var key = GetCacheKeyLogoutTime(request.Username);
                        _ = fusionCache.RemoveAsync(key).AsTask();
                        // Xoá lock IP
                        if (!ipInfo.IsPrivate)
                            _ = checkIpService.ClearLockAsync(ipInfo.IpAddress);
                        sw.Stop();
                        var elapsed = sw.ElapsedMilliseconds;
                        if (elapsed > 1000)
                        {
                            logger.Warning("Đăng nhập thành công: [{Elapsed} ms] {Username} {ClientIp}",
                                elapsed,
                                request.Username,
                                ipInfo);
                        }
                        else
                        {
                            logger.Information("Đăng nhập thành công: [{Elapsed} ms] {Username} {ClientIp}",
                                elapsed,
                                request.Username,
                                ipInfo);
                        }
                        return Results.Ok(
                            new Response<LoginResponse>(new LoginResponse(accessToken, tokenId, refreshToken.Token,
                                expiry)));
                    },
                    _ => Results.BadRequest(new Response<LoginResponse>(errorMessage))
                );
            },
            ex =>
            {
                sw.Stop();
                var elapsed = sw.ElapsedMilliseconds;
                logger.Error(ex, "Đăng nhập thất bại: [{Elapsed} ms] {Username} {ClientIp}",
                    elapsed,
                    request.Username,
                    ipInfo);
                if (ipInfo.IsPrivate)
                {
                    return Task.FromResult(Results.BadRequest(new Response<LoginResponse>(ex.Message)));
                }
                checkIpService.SetLockAsync(ipInfo.IpAddress);
                return Task.FromResult(Results.BadRequest(
                        new Response<LoginResponse>(
                            $"{ex.Message} {(count < 3 ? $"Bạn còn {3 - count} lần thử" : "")}")));
            }
        );
    }
}