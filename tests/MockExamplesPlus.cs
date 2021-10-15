using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Authorization.Samples;
using Authorization.Samples.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;
using Shouldly;

namespace Authorization.Tests
{
    public class MockExamplesPlus
    {
        private ServiceProvider _serviceProvider;
        private RequestDelegate _requestDelegate;

        [SetUp]
        public void Setup()
        {
            var startup = new Startup(new ConfigurationBuilder().Build());
            var env = new Mock<IWebHostEnvironment>();
            var authenticationHandlerProvider = new Mock<IAuthenticationHandlerProvider>();

            env.Setup(e => e.ApplicationName).Returns("Authorization.Samples");

            var services = new ServiceCollection()
                .AddSingleton(new DiagnosticListener(""))
                .AddSingleton<IHttpContextFactory, DefaultHttpContextFactory>()
                .AddSingleton(env.Object)
                .AddTransient(_ => authenticationHandlerProvider.Object)
                .AddLogging(b => b.AddNUnit());

            TestAuthenticationHandler.ClearSetups();
            authenticationHandlerProvider.Setup(p => p.GetHandlerAsync(It.IsAny<HttpContext>(), It.IsAny<string>()))
                .ReturnsAsync((HttpContext context, string scheme) => new TestAuthenticationHandler(scheme, context));

            startup.ConfigureServices(services);

            _serviceProvider = services.BuildServiceProvider();

            var app = new ApplicationBuilder(_serviceProvider);

            startup.Configure(app, env.Object);

            _requestDelegate = app.Build();
        }

        [Test]
        [TestCase("user1")]
        public async Task ShouldAuthorize(string username)
        {
            var httpContext = CreateContext("sample");

            TestAuthenticationHandler.SetupSuccess(AuthenticationSchemes.Ldap,
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, Roles.AppUser));

            await _requestDelegate(httpContext);
            
            httpContext.Response.StatusCode.ShouldBe(200);
            ReadResponseBody(httpContext).ShouldBe($"Hello, {username}");
        }

        private string ReadResponseBody(HttpContext context)
        {
            return Encoding.UTF8.GetString(((MemoryStream)context.Response.Body).ToArray());
        }
        
        private HttpContext CreateContext(string path)
        {
            var responseStream = new MemoryStream();
            var features = new FeatureCollection();

            features.Set<IHttpRequestFeature>(new HttpRequestFeature());
            features.Set<IHttpResponseFeature>(new HttpResponseFeature());

            var httpContext = _serviceProvider.GetRequiredService<IHttpContextFactory>().Create(features);

            httpContext.Request.Path = '/' + path;
            httpContext.Request.Method = HttpMethods.Get;
            httpContext.Response.Body = responseStream;

            return httpContext;
        }

        [TearDown]
        public void TearDown()
        {
            _serviceProvider.Dispose();
        }
    }
}