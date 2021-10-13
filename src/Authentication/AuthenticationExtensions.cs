using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Novell.Directory.Ldap;

namespace Authorization.Samples.Authentication
{
    public static class AuthenticationExtensions
    {
        public static AuthenticationBuilder AddLdap(this AuthenticationBuilder builder)
        {
            builder.Services.AddScoped<ILdapConnection, LdapConnection>();

            return builder.AddScheme<LdapAuthenticationOptions, LdapAuthenticationHandler>(
                LdapAuthenticationConstants.Scheme,
                _ => { });
        }

        public static IApplicationBuilder UseWwwAuthenticateChallenge(this IApplicationBuilder app)
        {
            return app.Use(async (context, next) =>
            {
                context.Response.OnStarting(async () =>
                {
                    if (context.Response.StatusCode == 401)
                        context.Response.Headers.Add("WWW-Authenticate", "Basic");
                });

                await next();
            });
        }
    }
}