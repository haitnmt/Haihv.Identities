using System.Net;

namespace Haihv.Identity.Ldap.Api.Exceptions;

/// <summary>
/// Lớp cơ sở cho các exception trong API LDAP.
/// </summary>
public abstract class LdapApiException : Exception
{
    /// <summary>
    /// Mã HTTP trả về cho client.
    /// </summary>
    public HttpStatusCode StatusCode { get; }

    /// <summary>
    /// Mã lỗi nội bộ.
    /// </summary>
    public string ErrorCode { get; }

    /// <summary>
    /// Khởi tạo một instance mới của <see cref="LdapApiException"/>.
    /// </summary>
    /// <param name="message">Thông báo lỗi.</param>
    /// <param name="statusCode">Mã HTTP trả về cho client.</param>
    /// <param name="errorCode">Mã lỗi nội bộ.</param>
    /// <param name="innerException">Exception gốc (nếu có).</param>
    protected LdapApiException(string message, HttpStatusCode statusCode, string errorCode, Exception? innerException = null)
        : base(message, innerException)
    {
        StatusCode = statusCode;
        ErrorCode = errorCode;
    }
}

/// <summary>
/// Exception khi xác thực thất bại.
/// </summary>
public class AuthenticationException : LdapApiException
{
    /// <summary>
    /// Khởi tạo một instance mới của <see cref="AuthenticationException"/>.
    /// </summary>
    /// <param name="message">Thông báo lỗi.</param>
    /// <param name="innerException">Exception gốc (nếu có).</param>
    public AuthenticationException(string message, Exception? innerException = null)
        : base(message, HttpStatusCode.Unauthorized, "AUTH_FAILED", innerException)
    {
    }
}

/// <summary>
/// Exception khi người dùng không được tìm thấy.
/// </summary>
public class UserNotFoundException : LdapApiException
{
    /// <summary>
    /// Khởi tạo một instance mới của <see cref="UserNotFoundException"/>.
    /// </summary>
    /// <param name="username">Tên người dùng không tìm thấy.</param>
    /// <param name="innerException">Exception gốc (nếu có).</param>
    public UserNotFoundException(string username, Exception? innerException = null)
        : base($"Người dùng không tồn tại [{username}]", HttpStatusCode.NotFound, "USER_NOT_FOUND", innerException)
    {
    }
}

/// <summary>
/// Exception khi cấu hình LDAP không hợp lệ.
/// </summary>
public class LdapConfigurationException : LdapApiException
{
    /// <summary>
    /// Khởi tạo một instance mới của <see cref="LdapConfigurationException"/>.
    /// </summary>
    /// <param name="message">Thông báo lỗi.</param>
    /// <param name="innerException">Exception gốc (nếu có).</param>
    public LdapConfigurationException(string message, Exception? innerException = null)
        : base(message, HttpStatusCode.InternalServerError, "LDAP_CONFIG_ERROR", innerException)
    {
    }
}

/// <summary>
/// Exception khi IP bị khóa do nhiều lần đăng nhập sai.
/// </summary>
public class IpLockedException : LdapApiException
{
    /// <summary>
    /// Thời gian còn lại (giây) trước khi IP được mở khóa.
    /// </summary>
    public long RemainingSeconds { get; }

    /// <summary>
    /// Khởi tạo một instance mới của <see cref="IpLockedException"/>.
    /// </summary>
    /// <param name="remainingSeconds">Thời gian còn lại (giây) trước khi IP được mở khóa.</param>
    /// <param name="innerException">Exception gốc (nếu có).</param>
    public IpLockedException(long remainingSeconds, Exception? innerException = null)
        : base($"Bạn đã đăng nhập sai quá nhiều, thử lại sau {remainingSeconds} giây!",
            HttpStatusCode.TooManyRequests, "IP_LOCKED", innerException)
    {
        RemainingSeconds = remainingSeconds;
    }
}

/// <summary>
/// Exception khi token không hợp lệ.
/// </summary>
public class InvalidTokenException : LdapApiException
{
    /// <summary>
    /// Khởi tạo một instance mới của <see cref="InvalidTokenException"/>.
    /// </summary>
    /// <param name="message">Thông báo lỗi.</param>
    /// <param name="innerException">Exception gốc (nếu có).</param>
    public InvalidTokenException(string message, Exception? innerException = null)
        : base(message, HttpStatusCode.Unauthorized, "INVALID_TOKEN", innerException)
    {
    }
}

/// <summary>
/// Exception khi thông tin đăng nhập không hợp lệ.
/// </summary>
public class InvalidCredentialsException : LdapApiException
{
    /// <summary>
    /// Số lần thử còn lại trước khi IP bị khóa.
    /// </summary>
    public int RemainingAttempts { get; }

    /// <summary>
    /// Khởi tạo một instance mới của <see cref="InvalidCredentialsException"/>.
    /// </summary>
    /// <param name="remainingAttempts">Số lần thử còn lại trước khi IP bị khóa.</param>
    /// <param name="innerException">Exception gốc (nếu có).</param>
    public InvalidCredentialsException(int remainingAttempts, Exception? innerException = null)
        : base($"Thông tin đăng nhập không chính xác! {(remainingAttempts > 0 ? $"Bạn còn {remainingAttempts} lần thử" : "")}",
            HttpStatusCode.Unauthorized, "INVALID_CREDENTIALS", innerException)
    {
        RemainingAttempts = remainingAttempts;
    }
}