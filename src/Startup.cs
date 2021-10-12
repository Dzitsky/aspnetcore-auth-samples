using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Authorization.Samples
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<LdapAuthenticationOptions>(Configuration.GetSection("LdapAuth"));

            services.AddAuthentication("Basic")
                .AddScheme<LdapAuthenticationOptions, LdapAuthenticationHandler>("Basic", op => { });
            services.AddAuthorization(op => op.DefaultPolicy =
                new AuthorizationPolicyBuilder("Basic").RequireAuthenticatedUser().Build());


            services.AddControllers();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();
            app.Use(async (context, next) =>
            {
                bool unauthorized = false;
                context.Response.OnStarting(async () =>
                {
                    if (unauthorized)
                        context.Response.Headers.Add("WWW-Authenticate", "Basic realm=\"my realm\"");
                });

                await next();

                if (context.Response.StatusCode == 401)
                    unauthorized = true;
            });
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
        }
    }

    public class LdapAuthenticationOptions : AuthenticationSchemeOptions
    {
        public string Host { get; set; }
        public string BindDn { get; set; }
        public string Password { get; set; }
        public string SearchBase { get; set; }
        public string SearchFilter { get; set; }
    }
}