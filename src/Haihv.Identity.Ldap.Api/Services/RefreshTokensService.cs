using System.Security.Cryptography;
using Haihv.Identity.Ldap.Api.Interfaces;
using Haihv.Identity.Ldap.Api.Models;
using LanguageExt.Common;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.Options;
using ILogger = Serilog.ILogger;

namespace Haihv.Identity.Ldap.Api.Services;

public sealed class RefreshTokensService(ILogger logger,
    HybridCache hybridCache,
    IOptions<JwtTokenOptions> options) : IRefreshTokensService
{
    private readonly TimeSpan _tokenExpiration = TimeSpan.FromDays(options.Value.ExpireRefreshTokenDays);
    private static string CacheKey(Guid clientId) => $"RefreshToken:{clientId}";
    
    private static string GenerateToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    }
    
    private ValueTask<RefreshToken> CreateToken(Guid clientId)
    {
        // Tạo token mới cho user (sử dụng sinh chuỗi ngẫu nhiên dài 128 ký tự)
        var refreshToken = new RefreshToken
        {
            UserId = clientId,
            Token = GenerateToken(),
            Expires = DateTimeOffset.Now.Add(_tokenExpiration)
        };

        return new ValueTask<RefreshToken>(refreshToken);
    }
    
    public async Task<Result<RefreshToken>> VerifyOrCreateAsync(Guid clientId, string samAccountName, string? token = null, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrEmpty(token))
            {
                return await GetOrCreateAsync(clientId, samAccountName, cancellationToken);
            }

            var refreshToken = await GetAndDeleteAsync(clientId, samAccountName, token, cancellationToken);
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
    
    private async Task<RefreshToken> GetOrCreateAsync(Guid clientId, string samAccountName, CancellationToken cancellationToken = default)
    {
        var key = CacheKey(clientId);
        // Tạo token mới nếu không tìm thấy trong cache
        var cacheEntryOptions = new HybridCacheEntryOptions
        {
            Expiration = _tokenExpiration,
            LocalCacheExpiration = TimeSpan.FromHours(1)
        };
        var refreshToken = await CreateToken(clientId);
        var hash = refreshToken.Token.GetHashCode().ToString();
        List<string> tags = string.IsNullOrWhiteSpace(hash) ? [samAccountName, clientId.ToString()] : 
            [samAccountName, clientId.ToString(), hash];
        // Lấy token từ cache
        return await hybridCache.GetOrCreateAsync(key, 
             _ => new ValueTask<RefreshToken>(refreshToken),
            cacheEntryOptions, 
            tags, 
            cancellationToken);
    }
    private async Task<RefreshToken?> GetAndDeleteAsync(Guid clientId, string samAccountName, string token, CancellationToken cancellationToken = default)
    {
        // Xóa token trong cache
        var tag = token.GetHashCode().ToString();
        if (!string.IsNullOrWhiteSpace(tag))
            await hybridCache.RemoveByTagAsync(tag, cancellationToken);
        // Lấy token từ cache
        return await GetOrCreateAsync(clientId, samAccountName, cancellationToken);
    }
    
}
