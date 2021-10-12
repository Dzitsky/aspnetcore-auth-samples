using System;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Authorization.Samples;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using Shouldly;

namespace Authorization.Tests
{
    public class Tests
    {
        private IHost host;
        private CancellationTokenSource cancel;
        
        [SetUp]
        public void Setup()
        {
            host = Host.CreateDefaultBuilder()
                .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>().UseTestServer())
                .ConfigureServices(services => services
                    .AddLogging(op => op.ClearProviders().AddNUnit()))
                .Build();
            cancel = new CancellationTokenSource(10_000);
        }

        [TearDown]
        public void TearDown()
        {
            host.Dispose();
            cancel.Dispose();
        }

        [Test]
        public async Task ShouldAuthorize()
        {
            await host.StartAsync(cancel.Token);

            var server = host.Services.GetRequiredService<IServer>().ShouldBeOfType<TestServer>();
            using var client = server.CreateClient();

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("appuser:CbEkn_0NNF1")));
            var res = await client.GetStringAsync("sample");
            
            res.ShouldBe("Hello, appuser");

            await host.StopAsync(cancel.Token);
        }
        
        [Test]
        public async Task ShouldCheckRole()
        {
            await host.StartAsync(cancel.Token);

            var server = host.Services.GetRequiredService<IServer>().ShouldBeOfType<TestServer>();
            using var client = server.CreateClient();

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("user2:Bu_6X2yULfs")));
            var res = await client.GetAsync("sample");
            
            res.StatusCode.ShouldBe(HttpStatusCode.Forbidden);

            await host.StopAsync(cancel.Token);
        }
    }
}