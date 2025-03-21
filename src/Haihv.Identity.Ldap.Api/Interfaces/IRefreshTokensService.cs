using Haihv.Identity.Ldap.Api.Models;
using LanguageExt.Common;

namespace Haihv.Identity.Ldap.Api.Interfaces;

public interface IRefreshTokensService
{
    Task<Result<RefreshToken>> VerifyOrCreateAsync(Guid clientId, string samAccountName,  string? token = null, CancellationToken cancellationToken = default);
}