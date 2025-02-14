using System.Security.Cryptography;
using Haihv.Api.Identity.Ldap.Interfaces;
using Haihv.Api.Identity.Ldap.Models;
using LanguageExt.Common;
using Microsoft.Extensions.Options;
using ZiggyCreatures.Caching.Fusion;
using ILogger = Serilog.ILogger;

namespace Haihv.Api.Identity.Ldap.Services;

public sealed class RefreshTokensService(ILogger logger,
    IFusionCache fusionCache,
    IOptions<JwtTokenOptions> options) : IRefreshTokensService
{
    private readonly TimeSpan _tokenExpiration = TimeSpan.FromDays(options.Value.ExpireRefreshTokenDays);
    private static string CacheKey(Guid clientId) => $"RefreshToken:{clientId}";
    
    private static string GenerateToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    }
    
    private RefreshToken CreateToken(Guid clientId)
    {
        // Tạo token mới cho user (sử dụng sinh chuỗi ngẫu nhiên dài 128 ký tự)
        var refreshToken = new RefreshToken
        {
            UserId = clientId,
            Token = GenerateToken(),
            Expires = DateTimeOffset.Now.Add(_tokenExpiration)
        };

        return refreshToken;
    }
    
    public async Task<Result<RefreshToken>> VerifyOrCreateAsync(Guid clientId, string? token = null, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrEmpty(token))
            {
                return await GetOrCreateAsync(clientId, cancellationToken);
            }

            var refreshToken = await GetAndDeleteAsync(clientId, token, cancellationToken);
            if (refreshToken is not null)
            {
                return refreshToken;
            }
            // Nếu token không hợp lệ thì trả về lỗi
            logger.Warning("Token not found or expires [{token}]", token);
            return new Result<RefreshToken>(new Exception("Token not found"));
        }
        catch (Exception ex)
        {
            logger.Error(ex, "Verify token failed [{token}]", token);
            return new Result<RefreshToken>(ex);
        }
    }
    
    private async Task<RefreshToken> GetOrCreateAsync(Guid clientId, CancellationToken cancellationToken = default)
    {
        var key = CacheKey(clientId);
        var token = await fusionCache.GetOrSetAsync(key, CreateToken(clientId).Token, _tokenExpiration, cancellationToken);
        return new RefreshToken
        {
            UserId = clientId,
            Token = token,
            Expires = DateTimeOffset.Now.Add(_tokenExpiration)
        };
    }
    private async Task<RefreshToken?> GetAndDeleteAsync(Guid clientId, string token, CancellationToken cancellationToken = default)
    {
        var key = CacheKey(clientId);
        var tokenInCache = await fusionCache.GetOrDefaultAsync<string>(key, token: cancellationToken);
        if(string.IsNullOrWhiteSpace(tokenInCache) || tokenInCache != token)
            return null;
        var refreshToken = CreateToken(clientId);
        await fusionCache.SetAsync(key, refreshToken.Token, _tokenExpiration, cancellationToken);
        return refreshToken;
    }
    
}
