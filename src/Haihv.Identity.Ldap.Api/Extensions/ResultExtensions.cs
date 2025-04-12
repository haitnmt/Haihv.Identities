using Haihv.Identity.Ldap.Api.Exceptions;
using LanguageExt.Common;

namespace Haihv.Identity.Ldap.Api.Extensions;

/// <summary>
/// Các phương thức mở rộng cho <see cref="Result{T}"/>.
/// </summary>
public static class ResultExtensions
{
    /// <summary>
    /// Chuyển đổi một <see cref="Result{T}"/> thành một giá trị hoặc ném ra một exception.
    /// </summary>
    /// <typeparam name="T">Kiểu dữ liệu của kết quả.</typeparam>
    /// <param name="result">Kết quả cần chuyển đổi.</param>
    /// <returns>Giá trị của kết quả nếu thành công.</returns>
    /// <exception cref="LdapApiException">Ném ra khi kết quả là lỗi.</exception>
    public static T ValueOrThrow<T>(this Result<T> result)
    {
        return result.Match(
            value => value,
            exception => throw ConvertToLdapApiException(exception)
        );
    }

    /// <summary>
    /// Chuyển đổi một <see cref="Result{T}"/> thành một giá trị hoặc một giá trị mặc định.
    /// </summary>
    /// <typeparam name="T">Kiểu dữ liệu của kết quả.</typeparam>
    /// <param name="result">Kết quả cần chuyển đổi.</param>
    /// <param name="defaultValue">Giá trị mặc định khi kết quả là lỗi.</param>
    /// <returns>Giá trị của kết quả nếu thành công, ngược lại là giá trị mặc định.</returns>
    public static T ValueOrDefault<T>(this Result<T> result, T defaultValue)
    {
        return result.Match(
            value => value,
            _ => defaultValue
        );
    }

    /// <summary>
    /// Chuyển đổi một <see cref="Result{T}"/> thành một giá trị hoặc null.
    /// </summary>
    /// <typeparam name="T">Kiểu dữ liệu của kết quả.</typeparam>
    /// <param name="result">Kết quả cần chuyển đổi.</param>
    /// <returns>Giá trị của kết quả nếu thành công, ngược lại là null.</returns>
    public static T? ValueOrNull<T>(this Result<T> result) where T : class
    {
        return result.Match(
            value => value,
            _ => null
        );
    }

    /// <summary>
    /// Chuyển đổi một exception thành một <see cref="LdapApiException"/>.
    /// </summary>
    /// <param name="exception">Exception cần chuyển đổi.</param>
    /// <returns>Một <see cref="LdapApiException"/>.</returns>
    private static Exception ConvertToLdapApiException(Exception exception)
    {
        // Nếu đã là LdapApiException thì trả về nguyên bản
        if (exception is LdapApiException)
        {
            return exception;
        }

        // Chuyển đổi các loại exception khác thành LdapApiException
        return exception switch
        {
            UnauthorizedAccessException => new InvalidTokenException("Không có quyền truy cập", exception),
            ArgumentException => new InvalidCredentialsException(0, exception),
            _ => new LdapConfigurationException(exception.Message, exception)
        };
    }
}