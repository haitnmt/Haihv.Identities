namespace Haihv.Identity.Ldap.Api.Models;

public sealed class RefreshToken
{
    public Guid UserId { get; init; } = Guid.Empty;
    public string Token { get; init; } = string.Empty;
    public DateTimeOffset Expires { get; init; } = DateTimeOffset.UtcNow.AddDays(7);
}