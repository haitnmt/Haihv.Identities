using System.Net;
using System.Text;
using Haihv.Identity.Ldap.Api.Endpoints;
using Haihv.Identity.Ldap.Api.Extensions;
using Haihv.Identity.Ldap.Api.Interfaces;
using Haihv.Identity.Ldap.Api.Services;
using LanguageExt.ClassInstances.Const;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);
// Set Console Support Vietnamese
Console.OutputEncoding = Encoding.UTF8;

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Add Serilog
builder.AddLogToElasticsearch();

// Add Caching
builder.AddFusionCache();

// Add service for LDAP
builder.AddLdapContext();
builder.Services.AddSingleton<IUserLdapService,UserLdapService>();
builder.Services.AddSingleton<IGroupLdapService,GroupLdapService>();
builder.Services.AddSingleton<IAuthenticateLdapService,AuthenticateLdapService>();

// Add Jwt
builder.Services.Configure<JwtTokenOptions>(builder.Configuration.GetSection("JwtOptions"));
builder.Services.AddSingleton<TokenProvider>();
builder.Services.AddSingleton<IRefreshTokensService, RefreshTokensService>();

// Add service for Check IP
builder.Services.AddSingleton<ICheckIpService, CheckIpService>();


// Configure CORS
var frontendUrls = builder.Configuration.GetSection("FrontendUrl").Get<string[]>();
if (frontendUrls is null || frontendUrls.Length == 0)
{
    frontendUrls = ["*"];
}
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(corsPolicyBuilder =>
    {
        corsPolicyBuilder.WithOrigins(frontendUrls)
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

// Use Cors
app.UseCors();

app.MapLoginEndpoints();
// Thêm Endpoint kiểm tra ứng dụng hoạt động
app.MapGet("/health", () => Results.Ok("OK")).WithName("GetHealth");

app.Run();

