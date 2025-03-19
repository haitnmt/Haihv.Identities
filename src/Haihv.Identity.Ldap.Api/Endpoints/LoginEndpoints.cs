using System.Diagnostics;
using Haihv.Identity.Ldap.Api.Interfaces;
using Haihv.Identity.Ldap.Api.Models;
using Haihv.Identity.Ldap.Api.Services;
using Haihv.Identity.Ldap.Api.Extensions;
using LanguageExt;
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
    }

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
        // Xác thực trong cơ sở dữ liệu trước:
        var result = await authenticateLdapService.Authenticate(request.Username, request.Password);

        return await result.Match<Task<IResult>>(async userLdap =>
            {
                var accessToken = tokenProvider.GenerateToken(userLdap);
                var tokenId = Guid.CreateVersion7();
                var resultRefreshToken = await refreshTokensService.VerifyOrCreateAsync(tokenId);
                var expiry = DateTime.UtcNow.AddMinutes(options.Value.ExpiryMinutes);
                // Lưu Cache thông tin nhóm của người dùng
                var key = UserEndpoints.GetCacheKey(userLdap.DistinguishedName);
                _ = fusionCache.GetOrSetAsync(key, await groupLdapService.GetAllGroupNameByDnAsync(userLdap.DistinguishedName)).AsTask();
                return resultRefreshToken.Match<IResult>(
                    refreshToken =>
                    {
                        if (!ipInfo.IsPrivate)
                            checkIpService.ClearLockAsync(ipInfo.IpAddress);
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