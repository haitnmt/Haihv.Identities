using Microsoft.Extensions.Caching.StackExchangeRedis;
using ZiggyCreatures.Caching.Fusion;
using ZiggyCreatures.Caching.Fusion.Serialization.SystemTextJson;

namespace Haihv.Api.Identity.Ldap.Extensions;

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
            })
            .WithSerializer(new FusionCacheSystemTextJsonSerializer());
        if (!string.IsNullOrWhiteSpace(redisConnectionString))
        {
            var instanceName = builder.Configuration["Redis:InstanceName"];
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
    }
}