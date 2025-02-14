using Haihv.Api.Identity.Ldap.Models;
using LanguageExt.Common;

namespace Haihv.Api.Identity.Ldap.Interfaces;

public interface IRefreshTokensService
{
    Task<Result<RefreshToken>> VerifyOrCreateAsync(Guid clientId, string? token = null, CancellationToken cancellationToken = default);
}