using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Authorization.Samples.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Authorization.Samples
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<LdapAuthenticationOptions>(Configuration.GetSection("Ldap"));

            services.AddAuthentication(AuthenticationSchemes.Ldap).AddLdap();

            services.AddAuthorization(op =>
            {
                op.DefaultPolicy =
                    new AuthorizationPolicyBuilder(AuthenticationSchemes.Ldap).RequireAuthenticatedUser()
                        .Build();
                op.AddPolicy(Policies.RequireTelephoneNumber,
                    new AuthorizationPolicyBuilder(AuthenticationSchemes.Ldap)
                        .RequireAuthenticatedUser()
                        .AddRequirements(new HasAllAdditionalAttributesRequirement())
                        .Build());
                op.AddPolicy(Policies.RequireGlobalAdminRealm,
                    new AuthorizationPolicyBuilder(AuthenticationSchemes.Ldap)
                        .RequireAuthenticatedUser()
                        .RequireClaim(AppClaimTypes.AdminRealm, "global")
                        .Build());

                op.AddPolicy(Policies.RequireAge18Plus,
                    new AuthorizationPolicyBuilder(AuthenticationSchemes.Ldap)
                        .RequireAuthenticatedUser()
                        .AddRequirements(new MinAgeRequirement(18))
                        .Build());
            });

            services.AddTransient<IAuthorizationHandler, AgeAuthorizationHandler>();
            services.AddTransient<IAuthorizationHandler, HasAllAdditionalAttributesAuthorizationHandler>();
            services.AddControllers();
        }

        public class MinAgeRequirement : IAuthorizationRequirement
        {
            public MinAgeRequirement(int minAge)
            {
                MinAge = minAge;
            }

            public int MinAge { get; }
        }

        public class AgeAuthorizationHandler : AuthorizationHandler<MinAgeRequirement>
        {
            protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context,
                MinAgeRequirement requirement)
            {
                if (int.TryParse(context.User.Claims.FirstOrDefault(c => c.Type == AppClaimTypes.Age)?.Value,
                    out var age))
                    if (age >= requirement.MinAge)
                        context.Succeed(requirement);
                    else
                        context.Fail();
            }
        }

        public class HasAllAdditionalAttributesRequirement : IAuthorizationRequirement
        {
        }

        public class
            HasAllAdditionalAttributesAuthorizationHandler : AuthorizationHandler<HasAllAdditionalAttributesRequirement>
        {
            private IReadOnlyList<string> attributes;

            public HasAllAdditionalAttributesAuthorizationHandler(IOptions<LdapAuthenticationOptions> options)
            {
                attributes = options.Value.AdditionalClaimAttributes;
            }

            protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context,
                HasAllAdditionalAttributesRequirement requirement)
            {
                if (context.User.Claims.Join(attributes, c => c.Type, c => c, (a, b) => true).Count() ==
                    attributes.Count)
                    context.Succeed(requirement);
            }
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
                app.UseDeveloperExceptionPage();
            else
                app.UseHsts();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints => endpoints.MapControllers());
        }
    }
}