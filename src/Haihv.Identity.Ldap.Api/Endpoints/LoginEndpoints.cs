using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using Haihv.Identity.Ldap.Api.Interfaces;
using Haihv.Identity.Ldap.Api.Models;
using Haihv.Identity.Ldap.Api.Services;
using Haihv.Identity.Ldap.Api.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
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
        TokenProvider tokenProvider,
        IRefreshTokensService refreshTokensService,
        ICheckIpService checkIpService,
        IOptions<JwtTokenOptions> options,
        HttpContext httpContext)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
        {
            return Results.BadRequest(new Response<LoginResponse>("Tên đăng nhập và mật khẩu không được để trống!"));
        }
        var ipAddr = httpContext.GetIpAddress();
        var (count, exprSecond)  = await checkIpService.CheckLockAsync(ipAddr);
        if (exprSecond > 0)
        {
            return Results.BadRequest(new Response<LoginResponse>($"Bạn đã đăng nhập sai quá nhiều, thử lại sau {exprSecond} giây!"));
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
                return resultRefreshToken.Match<IResult>(
                    refreshToken =>
                    {
                        checkIpService.ClearLockAsync(ipAddr);
                        sw.Stop();
                        var elapsed = sw.ElapsedMilliseconds;
                        if (elapsed > 1000)
                        {
                            logger.Warning("Đăng nhập thành công: [{Elapsed} ms] {Username} {ClientIp}",
                                elapsed,
                                request.Username,
                                ipAddr);
                        }
                        else
                        {
                            logger.Information("Đăng nhập thành công: [{Elapsed} ms] {Username} {ClientIp}",
                                elapsed,
                                request.Username,
                                ipAddr);
                        }
                        return Results.Ok(
                            new Response<LoginResponse>(new LoginResponse(accessToken, tokenId, refreshToken.Token, expiry)));
                    },
                    _ => Results.BadRequest(new Response<LoginResponse>(errorMessage))
                );
            },
            ex =>
            {
                checkIpService.SetLockAsync(ipAddr);
                sw.Stop();
                var elapsed = sw.ElapsedMilliseconds;
                logger.Error(ex, "Đăng nhập thất bại: [{Elapsed} ms] {Username} {ClientIp}",
                    elapsed,
                    request.Username,
                    ipAddr);
                return Task.FromResult(Results.BadRequest(new Response<LoginResponse>($"{errorMessage} {(count < 3 ? $"Bạn còn {3 - count} lần thử" : "")}")));
            }
        );
    }
    
    private static string GetIpAddress(this HttpContext httpContext)
    {
        string? ipAddress = null;
    
        // Order headers by proxy chain priority (last proxy to first)
        var headerKeys = new[]
        {
            "CF-Connecting-IP",   // Highest priority - Cloudflare original client IP
            "True-Client-IP",     // Alternative Cloudflare header
            "X-Original-For",     // HAProxy
            "X-Forwarded-For",    // General proxy header (will contain chain of IPs)
            "X-Real-IP",          // Nginx
            "REMOTE_ADDR"         // Fallback
        };

        foreach (var headerKey in headerKeys)
        {
            if (!httpContext.Request.Headers.TryGetValue(headerKey, out var headerValue)) continue;
            ipAddress = headerValue.FirstOrDefault()?.Split(',')[0].Trim();
            if (!string.IsNullOrWhiteSpace(ipAddress))
                break;
        }

        // Fallback to RemoteIpAddress if no proxy headers found
        if (string.IsNullOrWhiteSpace(ipAddress) && httpContext.Connection.RemoteIpAddress != null)
        {
            ipAddress = httpContext.Connection.RemoteIpAddress.ToString();
        }

        return ipAddress ?? "Unknown";
    }
}