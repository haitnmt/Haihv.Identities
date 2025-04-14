using Microsoft.Extensions.Caching.Hybrid;

namespace Haihv.Identity.Ldap.Api.Services;

public interface ICheckIpService
{
    /// <summary>
    /// Kiểm tra xem IP có bị khóa không.
    /// </summary>
    /// <param name="ip">Địa chỉ IP cần kiểm tra.</param>
    /// <returns>
    /// Thời gian còn lại của khóa theo giây.
    /// </returns>
    Task<(int Count, long ExprSecond)> CheckLockAsync(string ip);
    /// <summary>
    /// Đặt khóa cho IP.
    /// </summary>
    /// <param name="ip">
    /// Địa chỉ IP cần đặt khóa.
    /// </param>
    Task SetLockAsync(string ip, int maxCount = 3, int maxCount1Day = 10);

    /// <summary>
    /// Xóa khóa của IP.
    /// </summary>
    /// <param name="ip">
    /// Địa chỉ IP cần xóa khóa.
    /// </param>
    Task ClearLockAsync(string ip);


}

public sealed class CheckIpService(HybridCache hybridCache, int secondStep = 300) : ICheckIpService
{
    private const string Key = "CheckIp";
    private readonly int SecondStep = secondStep;
    private static string LockKey(string ip) => $"{Key}:Lock:{ip}";

    /// <summary>
    /// Kiểm tra xem IP có bị khóa không.
    /// </summary>
    /// <param name="ip">Địa chỉ IP cần kiểm tra.</param>
    /// <returns>
    /// Thời gian còn lại của khóa theo giây.
    /// </returns>
    public async Task<(int Count, long ExprSecond)> CheckLockAsync(string ip)
    {
        var lockInfo = await hybridCache.GetOrCreateAsync(LockKey(ip),
            _ => ValueTask.FromResult<LockInfo?>(null));
        return lockInfo is null ? (0, 0L) :
            // Tính thời gian lock còn lại theo giây (làm tròn kiểu long)
            (lockInfo.Count, (long)Math.Ceiling((lockInfo.ExprTime - DateTime.Now).TotalSeconds));
    }

    /// <summary>
    /// Đặt khóa cho IP.
    /// </summary>
    /// <param name="ip">
    /// Địa chỉ IP cần đặt khóa.
    /// </param>
    /// <param name="maxCount">
    /// Số lần thử đăng nhập tối đa trước khi bị khóa.
    /// </param>
    /// <param name="maxCount1Day">
    /// Số lần thử đăng nhập tối đa trong 1 ngày trước khi bị khóa.
    /// </param>
    /// <remarks>
    /// Nếu không truyền giá trị cho <paramref name="maxCount"/> và <paramref name="maxCount1Day"/>,
    /// thì sẽ sử dụng giá trị mặc định là 3 và 10.
    /// </remarks>
    public async Task SetLockAsync(string ip, int maxCount = 3, int maxCount1Day = 10)
    {
        var lockInfo = await hybridCache.GetOrCreateAsync(LockKey(ip),
            _ => ValueTask.FromResult<LockInfo?>(null));
        double expSecond = 0;
        const int totalSecond1Day = 86400;
        if (lockInfo is null)
        {
            lockInfo = new LockInfo
            {
                Count = 1
            };
        }
        else if (lockInfo.ExprTime >= DateTime.Now.AddDays(1))
        {
            lockInfo.Count = maxCount1Day;
            expSecond = totalSecond1Day;
        }
        else
        {
            lockInfo.Count++;
            if (lockInfo.Count > maxCount)
            {
                expSecond = Math.Pow(2, lockInfo.Count - maxCount) * SecondStep;
                expSecond = expSecond > totalSecond1Day ? totalSecond1Day : expSecond;
            }
        }
        lockInfo.ExprTime = DateTime.Now.AddSeconds(expSecond);
        await hybridCache.SetAsync(LockKey(ip), lockInfo);
    }

    /// <summary>
    /// Xóa khóa của IP.
    /// </summary>
    /// <param name="ip">
    /// Địa chỉ IP cần xóa khóa.
    /// </param>
    public async Task ClearLockAsync(string ip)
    {
        await hybridCache.RemoveAsync(LockKey(ip));
    }

    private sealed class LockInfo(int count, DateTime exprTime)
    {
        public int Count { get; set; } = count;
        public DateTime ExprTime { get; set; } = exprTime;

        public LockInfo() : this(0, DateTime.MinValue)
        { }
    }
}