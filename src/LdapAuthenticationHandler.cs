using System;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Novell.Directory.Ldap;

namespace Authorization.Samples
{
    public class LdapAuthenticationHandler : AuthenticationHandler<LdapAuthenticationOptions>
    {
        private const string MemberOfAttribute = "memberOf";
        private const string CnAttribute = "cn";

        public LdapAuthenticationHandler(IOptionsMonitor<LdapAuthenticationOptions> options, ILoggerFactory logger,
            UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        private (string username, string password) ReadCredentials(string basic)
        {
            var auth = Encoding.UTF8.GetString(Convert.FromBase64String(basic["Basic ".Length..])).Split(':');

            return (auth[0], auth[1]);
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue("Authorization", out var authorization) ||
                !authorization[0].StartsWith("Basic "))
                return AuthenticateResult.NoResult();

            var config = OptionsMonitor.CurrentValue;
            var (username, password) = ReadCredentials(authorization);
            using var connection = new LdapConnection();

            using (Logger.BeginScope(new { config.Host }))
                Logger.LogDebug("Connecting LDAP server...");

            connection.Connect(config.Host, LdapConnection.DefaultPort);

            using (Logger.BeginScope(new { config.BindDn }))
                Logger.LogDebug("Binding...");

            connection.Bind(config.BindDn, config.Password);

            var searchFilter = string.Format(config.SearchFilter, username);

            using (Logger.BeginScope(new { searchFilter }))
                Logger.LogDebug("Searching...");

            var result = connection.Search(
                config.SearchBase,
                LdapConnection.ScopeSub,
                searchFilter,
                new[]
                {
                    CnAttribute,
                    MemberOfAttribute
                },
                false
            );

            if (!result.HasMore())
                return AuthenticateResult.Fail("Invalid credentials");

            var user = result.Next();

            try
            {
                connection.Bind(user.Dn, password);
            }
            catch (LdapException)
            {
                return AuthenticateResult.Fail("Invalid credentials");
            }

            var cn = user.GetAttribute(CnAttribute);
            if (cn == null)
            {
                return AuthenticateResult.Fail("Problem with your account, contact administrator");
            }

            var memberAttr = user.GetAttribute(MemberOfAttribute);
            if (memberAttr == null)
            {
                return AuthenticateResult.Fail("Problem with your account, contact administrator");
            }

            var claims = (from g in memberAttr.StringValueArray
                let match = Regex.Match(g, "^CN=([^,]*)", RegexOptions.IgnoreCase)
                where match.Success
                select new Claim("role", match.Groups[1].Value)).Append(new Claim("name", cn.StringValue));
            var identity = new ClaimsIdentity(claims, nameof(LdapAuthenticationHandler), "name", "role");

            return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity),
                "Basic"));
        }
    }
}