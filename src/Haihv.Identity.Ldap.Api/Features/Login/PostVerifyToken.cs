using Carter;
using Haihv.Identity.Ldap.Api.Services;
using MediatR;

namespace Haihv.Identity.Ldap.Api.Features.Login;

public static class PostVerifyToken
{
    public record Query : IRequest<bool>;

    public class Handler(
        IHttpContextAccessor httpContextAccessor,
        TokenProvider tokenProvider) : IRequestHandler<Query, bool>
    {
        public async Task<bool> Handle(Query request, CancellationToken cancellationToken)
        {
            var httpContext = httpContextAccessor.HttpContext
                              ?? throw new InvalidOperationException("HttpContext không khả dụng");
            // Lấy thông tin đăng nhập từ context header Bearer token
            var accessToken =  httpContext.Request.Headers.Authorization.ToString().Replace("Bearer ", "");
            return await tokenProvider.VerifyAccessToken(accessToken, cancellationToken);
        }
    }
    public class Endpoint : ICarterModule
    {
        public void AddRoutes(IEndpointRouteBuilder app)
        {
            app.MapPost("/api/verify", async (ISender sender) =>
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