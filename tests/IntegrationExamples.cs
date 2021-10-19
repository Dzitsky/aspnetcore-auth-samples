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
using Newtonsoft.Json.Linq;
using NUnit.Framework;
using Shouldly;

namespace Authorization.Tests
{
    // To make samples work:
    // docker run --rm -it --name openldap -p 389:389 -e LDAP_DOMAIN="some-company.local" -e LDAP_ADMIN_PASSWORD="So+QqZYY13p6" -e LDAP_READONLY_USER=true -e LDAP_READONLY_USER_USERNAME="readonly" -e LDAP_READONLY_USER_PASSWORD="w_pJlB8JccJ2Uw" -e LDAP_TLS=false -v "$PWD/../ldap":/container/service/slapd/assets/config/bootstrap/ldif/custom osixia/openldap --copy-service
    public class IntegrationExamples
    {
        private CancellationTokenSource cancel;
        private IHost host;

        private AuthenticationHeaderValue AppUser => new("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("appuser:CbEkn_0NNF1")));

        private AuthenticationHeaderValue User2 => new("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("user2:Bu_6X2yULfs")));

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
        public async Task ShouldAuthorizeJwt()
        {
            await host.StartAsync(cancel.Token);

            var server = host.Services.GetRequiredService<IServer>().ShouldBeOfType<TestServer>();
            using var client = server.CreateClient();

            var dd = JToken.Parse(Encoding.UTF8.GetString(Convert.FromBase64String("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")));
            // Tokens can be generated at https://jwt.io/
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.C_oJC0CHkDiV1yT_Wiij5IfQqDgPylMhMKhd32H_CoQ");
            var res = await client.GetStringAsync("jwt_hello");

            res.ShouldBe("Hello, John Doe!");

            await host.StopAsync(cancel.Token);
        }
        
        
        [Test]
        public async Task ShouldCheckOneTimeJwt()
        {
            await host.StartAsync(cancel.Token);

            var server = host.Services.GetRequiredService<IServer>().ShouldBeOfType<TestServer>();
            using var client = server.CreateClient();

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ1aWQiOiJYdUFIcm1FdEc5alYifQ._8C_iIPPRhxUNgQen8wE6Q2RZ_fLh-SiWVxsQxzYPow");
            var res = await client.GetStringAsync("jwt_one_time");

            res.ShouldContain("XuAHrmEtG9jV");

            await host.StopAsync(cancel.Token);
            
            var res2 = await client.GetAsync("jwt_one_time");

            res2.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        }

        [Test]
        public async Task ShouldAuthorize()
        {
            await host.StartAsync(cancel.Token);

            var server = host.Services.GetRequiredService<IServer>().ShouldBeOfType<TestServer>();
            using var client = server.CreateClient();

            client.DefaultRequestHeaders.Authorization = AppUser;
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

            client.DefaultRequestHeaders.Authorization = User2;
            var res = await client.GetAsync("sample");

            res.StatusCode.ShouldBe(HttpStatusCode.Forbidden);

            await host.StopAsync(cancel.Token);
        }

        [Test]
        public async Task ShouldShowTelephoneNumber()
        {
            await host.StartAsync(cancel.Token);

            var server = host.Services.GetRequiredService<IServer>().ShouldBeOfType<TestServer>();
            using var client = server.CreateClient();

            client.DefaultRequestHeaders.Authorization = User2;
            var res = await client.GetStringAsync("telephone_number");

            res.ShouldBe("Your telephone number is 99625382");

            await host.StopAsync(cancel.Token);
        }

        [Test]
        public async Task ShouldCheckTelephoneNumberClaim()
        {
            await host.StartAsync(cancel.Token);

            var server = host.Services.GetRequiredService<IServer>().ShouldBeOfType<TestServer>();
            using var client = server.CreateClient();

            client.DefaultRequestHeaders.Authorization = AppUser;
            var res = await client.GetAsync("telephone_number");

            res.StatusCode.ShouldBe(HttpStatusCode.Forbidden);

            await host.StopAsync(cancel.Token);
        }
    }
}