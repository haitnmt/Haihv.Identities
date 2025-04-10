using Carter;
using Haihv.Identity.Ldap.Api.Extensions;
using Haihv.Identity.Ldap.Api.Settings;
using MediatR;
using Microsoft.Extensions.Caching.Hybrid;
using ILogger = Serilog.ILogger;

namespace Haihv.Identity.Ldap.Api.Features.Login;

public static class VerifyToken
{
    public record Query : IRequest<bool>;

    public class Handler(
        IHttpContextAccessor httpContextAccessor,
        ILogger logger,
        HybridCache hybridCache) : IRequestHandler<Query, bool>
    {
        public async Task<bool> Handle(Query request, CancellationToken cancellationToken)
        {
            var httpContext = httpContextAccessor.HttpContext
                              ?? throw new InvalidOperationException("HttpContext không khả dụng");
            return await httpContext.VerifyToken(hybridCache, logger, cancellationToken);
        }
    }
    public class Endpoint : ICarterModule
    {
        public void AddRoutes(IEndpointRouteBuilder app)
        {
            app.MapGet("/api/verify", async (ISender sender) =>
                {
                    try
                    {
                        var response = await sender.Send(new Query());
                        return response ? Results.Ok("Token hợp lệ!") : Results.Unauthorized();
                    } 
                    catch (Exception e)
                    {
                        return Results.BadRequest(e.Message);
                    }
                })
                .WithTags("Login")
                .RequireAuthorization();
        }
    }
}