using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Text.Json;
using System.Text.Json.Serialization;
using Haihv.Identity.Ldap.Api.Interfaces;
using Haihv.Identity.Ldap.Api.Models;
using Haihv.Identity.Ldap.Api.Services;
using Haihv.Identity.Ldap.Api.Extensions;
using Microsoft.AspNetCore.Mvc;
using ILogger = Serilog.ILogger;
using LoginRequest = Haihv.Identity.Ldap.Api.Models.LoginRequest;

namespace Haihv.Identity.Ldap.Api.Endpoints;

public static class LoginEndpoints
{
    public static void MapLoginEndpoints(this WebApplication app)
    {
        
        app.MapPost("/login", Login);
    }

    private record LoginResponse(string AccessToken, Guid ClientId, string RefreshToken);
    private static async Task<IResult> Login([FromBody] LoginRequest request,
        ILogger logger,
        IAuthenticateLdapService authenticateLdapService,
        TokenProvider tokenProvider,
        IRefreshTokensService refreshTokensService,
        HttpContext httpContext)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
        {
            return Results.BadRequest(new Response<LoginResponse>("Tên đăng nhập và mật khẩu không được để trống!"));
        }
        var user = new User(request.Username, request.Password);
        var sw = Stopwatch.StartNew();
        // Xác thực trong cơ sở dữ liệu trước:
        var result = await authenticateLdapService.Authenticate(request.Username, request.Password);
        return await result.Match<Task<IResult>>(async userLdap =>  
            {
                var accessToken = tokenProvider.GenerateToken(userLdap);
                var clientId = Guid.CreateVersion7();
                var resultRefreshToken = await refreshTokensService.VerifyOrCreateAsync(clientId);
                return resultRefreshToken.Match<IResult>(
                    refreshToken =>
                    {
                        sw.Stop();
                        var elapsed = sw.ElapsedMilliseconds;
                        if (elapsed > 1000)
                        {
                            logger.Warning("Đăng nhập thành công: {Info} [{Elapsed} ms]",
                                httpContext.GetLogInfo(request.Username), elapsed);
                        }
                        else
                        {
                            logger.Information("Đăng nhập thành công: {Info} [{Elapsed} ms]",
                                httpContext.GetLogInfo(request.Username), elapsed);
                        }
                        return Results.Ok(
                            new Response<LoginResponse>(new LoginResponse(accessToken, clientId, refreshToken.Token)));
                    },
                    ex => Results.BadRequest(new Response<LoginResponse>(GetExceptionMessage(ex)))
                );
            },
            ex =>
            {
                sw.Stop();
                var elapsed = sw.ElapsedMilliseconds;
                logger.Error(ex, "Đăng nhập thất bại: {Info} [{Elapsed} ms]",
                    httpContext.GetLogInfo(request.Username), elapsed);
                return Task.FromResult(Results.BadRequest(new Response<LoginResponse>(GetExceptionMessage(ex))));
            }
        );

        string GetExceptionMessage(Exception ex)
        {
            return ex switch
            {
                LdapException ldapException =>
                    ldapException.ErrorCode switch
                    {
                        49 => "Tên đăng nhập hoặc mật khẩu không chính xác!",
                        _ => ex.Message
                    },
                _ => ex.Message
            };
        }
    }
    
    
    private class LogInfo   
    {
        [JsonPropertyName("clientIp")]
        public string ClientIp { get; set; } = string.Empty;
        [JsonPropertyName("username")]
        public string Username { get; set; } = string.Empty;
        [JsonPropertyName("userAgent")]
        public string UserAgent { get; set; } = string.Empty;
        [JsonPropertyName("url")]
        public string Url { get; set; } = string.Empty;
        [JsonPropertyName("hashBody")]
        public string? HashBody { get; set; } = string.Empty;
        [JsonPropertyName("queryString")]
        public string? QueryString { get; set; } = string.Empty;
    }
    private static string GetLogInfo(this HttpContext httpContext, string? username = null)
    {
        return JsonSerializer.Serialize(new LogInfo
        {
            ClientIp = httpContext.Connection.LocalIpAddress?.ToString() ?? string.Empty,
            Username = username ?? httpContext.User.Identity?.Name ?? string.Empty,
            UserAgent = httpContext.Request.Headers.UserAgent.ToString(),
            Url = httpContext.Request.Path.Value ?? string.Empty,
            HashBody = httpContext.Request.Body.ToString().ComputeHash() ?? string.Empty,
            QueryString = httpContext.Request.QueryString.Value ?? string.Empty
        });
    }
    
}