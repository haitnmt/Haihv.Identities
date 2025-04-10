namespace Haihv.Identity.Ldap.Api.Services;

public static class JwtTokenOptionsExtensions
{
    public static void AddJwtTokenOptions(this IHostApplicationBuilder builder, string sectionName)
    {
        // Add Jwt
        builder.Services.Configure<JwtTokenOptions>(builder.Configuration.GetSection(sectionName));
    }
    public static JwtTokenOptions GetJwtTokenOptions(this IConfiguration configuration, string sectionName)
    {
        var options = new JwtTokenOptions();
        configuration.GetSection("JwtOptions").Bind(options);
        return options;
    }
}