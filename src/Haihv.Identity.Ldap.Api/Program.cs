using System.Text;
using Carter;
using Haihv.Identity.Ldap.Api.Extensions;
using Haihv.Identity.Ldap.Api.Interfaces;
using Haihv.Identity.Ldap.Api.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;


var builder = WebApplication.CreateBuilder(args);
// Set Console Support Vietnamese
Console.OutputEncoding = Encoding.UTF8;


// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Add Serilog
builder.AddLogToElasticsearch();

// Add Caching
builder.AddCache();

// Add service for LDAP
builder.AddLdapContext();
builder.Services.AddSingleton<IUserLdapService,UserLdapService>();
builder.Services.AddSingleton<IGroupLdapService,GroupLdapService>();
builder.Services.AddSingleton<IAuthenticateLdapService,AuthenticateLdapService>();

// Add Jwt
const string jwtSectionName = "JwtOptions";
builder.AddJwtTokenOptions(jwtSectionName);
builder.Services.AddSingleton<TokenProvider>();

// Add service for Check IP
builder.Services.AddSingleton<ICheckIpService, CheckIpService>();

// Add HttpContextAccessor
builder.Services.AddHttpContextAccessor();

// Add service Authentication and Authorization for Identity Server
builder.Services.AddAuthorizationBuilder();

var jwtTokenOptions = builder.Configuration.GetJwtTokenOptions(jwtSectionName);
builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtTokenOptions.SecretKey)),
            ValidIssuer = jwtTokenOptions.Issuer,
            ValidAudience = jwtTokenOptions.Audience,
            ClockSkew = TimeSpan.Zero
        };
    });
// Configure CORS
var frontendUrls = builder.Configuration.GetSection("FrontendUrl").Get<string[]>();
if (frontendUrls is null || frontendUrls.Length == 0)
{
    // Không thể sử dụng wildcard "*" với AllowCredentials()
    // Nếu không có URL cụ thể, sử dụng localhost mặc định
    frontendUrls = ["http://localhost:5167", "https://localhost:7063"];
}
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(corsPolicyBuilder =>
    {
        // Kiểm tra xem có wildcard "*" trong danh sách không
        if (frontendUrls.Contains("*"))
        {
            // Nếu có wildcard, không sử dụng AllowCredentials
            corsPolicyBuilder.AllowAnyOrigin()
                .AllowAnyHeader()
                .AllowAnyMethod();
        }
        else
        {
            // Nếu không có wildcard, sử dụng AllowCredentials
            corsPolicyBuilder.WithOrigins(frontendUrls)
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials();
        }
    });
});
builder.Services.AddMediatR(cfg =>
    cfg.RegisterServicesFromAssembly(typeof(Program).Assembly));
builder.Services.AddCarter();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

// Thêm middleware xử lý exception toàn cục
app.UseGlobalExceptionHandler();

app.UseHttpsRedirection();

// Use Cors
app.UseCors();
// Thêm Endpoint kiểm tra ứng dụng hoạt động
app.MapGet("/health", () => Results.Ok("OK")).WithName("GetHealth").WithTags("Health");

// Authentication and Authorization
app.UseAuthentication();
app.UseAuthorization();
app.MapCarter();

app.Run();

