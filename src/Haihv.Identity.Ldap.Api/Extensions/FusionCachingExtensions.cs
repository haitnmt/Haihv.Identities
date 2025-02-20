using Microsoft.Extensions.Caching.StackExchangeRedis;
using StackExchange.Redis;
using ZiggyCreatures.Caching.Fusion;
using ZiggyCreatures.Caching.Fusion.Serialization.SystemTextJson;

namespace Haihv.Identity.Ldap.Api.Extensions;

public static class HybridCachingExtensions
{
    public static void AddFusionCache(this IHostApplicationBuilder builder)
    {
        //Add MemoryCache
        var services = builder.Services;
        
        // Configure Redis
        var redisConnectionString = builder.Configuration["Redis:ConnectionString"];
        
        services.AddMemoryCache();
        var fusionOptions = services.AddFusionCache()
            .WithDefaultEntryOptions(options =>
            {
                options.Duration = TimeSpan.FromMinutes(5);
                options.IsFailSafeEnabled = true;
                options.FailSafeThrottleDuration = TimeSpan.FromSeconds(15);
                options.FailSafeThrottleDuration = TimeSpan.FromDays(1);
                options.FailSafeMaxDuration = TimeSpan.FromDays(7);
            })
            .WithSerializer(new FusionCacheSystemTextJsonSerializer());
        var instanceName = builder.Configuration["Redis:InstanceName"];
        if (!string.IsNullOrWhiteSpace(redisConnectionString))
        {
            fusionOptions.WithDistributedCache(
                new RedisCache(
                    new RedisCacheOptions
                    {
                        Configuration = redisConnectionString,
                        InstanceName = instanceName
                    }
                ));
        }
        
        fusionOptions.AsHybridCache();
        
        // Clear redis cache when application start
        if (string.IsNullOrWhiteSpace(redisConnectionString)) return;
        var redis = ConnectionMultiplexer.Connect(redisConnectionString);
        // Clear all databases in Redis server with prefix instanceName
        foreach (var endPoint in redis.GetEndPoints())
        {
            var server = redis.GetServer(endPoint);
            foreach (var key in server.Keys(pattern: $"{instanceName}*"))
            {
                redis.GetDatabase().KeyDelete(key);
            }
        }
    }
}