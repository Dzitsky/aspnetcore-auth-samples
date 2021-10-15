using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Novell.Directory.Ldap;

namespace Authorization.Samples.Authentication
{
    public class LdapAuthenticationHandler : AuthenticationHandler<LdapAuthenticationOptions>
    {
        private const string MemberOfAttribute = "memberOf";
        private const string CnAttribute = "cn";

        private readonly ILdapConnection _connection;

        public LdapAuthenticationHandler(
            ILdapConnection connection,
            IOptionsMonitor<LdapAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock) : base(options, logger, encoder, clock)
        {
            _connection = connection;
        }

        private (string username, string password) ReadCredentials(string basic)
        {
            var auth = Encoding.UTF8.GetString(Convert.FromBase64String(basic["Basic ".Length..])).Split(':');

            return (auth[0], auth[1]);
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            Context.Response.Headers.Add("WWW-Authenticate", "Basic");

            return Task.CompletedTask;
        }
        
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue("Authorization", out var authorization) ||
                !authorization[0].StartsWith("Basic "))
                return AuthenticateResult.NoResult();

            var config = OptionsMonitor.CurrentValue;
            var (username, password) = ReadCredentials(authorization);

            using (Logger.BeginScope(new { config.Host }))
            {
                Logger.LogDebug("Connecting LDAP server...");
            }

            _connection.Connect(config.Host, LdapConnection.DefaultPort);

            using (Logger.BeginScope(new { config.BindDn }))
            {
                Logger.LogDebug("Binding...");
            }

            _connection.Bind(config.BindDn, config.Password);

            var searchFilter = string.Format(config.SearchFilter, username);

            using (Logger.BeginScope(new { searchFilter }))
            {
                Logger.LogDebug("Searching...");
            }

            var result = _connection.Search(
                config.SearchBase,
                LdapConnection.ScopeSub,
                searchFilter,
                (config.AdditionalClaimAttributes ?? Array.Empty<string>()).Append(CnAttribute)
                .Append(MemberOfAttribute).ToArray(),
                false
            );

            if (!result.HasMore())
                return AuthenticateResult.Fail("Invalid credentials");

            var user = result.Next();

            try
            {
                _connection.Bind(user.Dn, password);
            }
            catch (LdapException)
            {
                return AuthenticateResult.Fail("Invalid credentials");
            }

            var attributes = user.GetAttributeSet();
            var cn = attributes[CnAttribute];
            var claims = new List<Claim> { new(ClaimTypes.Name, cn.StringValue) };

            if (attributes.TryGetValue(MemberOfAttribute, out var memberAttr))
                claims.AddRange(from g in memberAttr.StringValueArray
                    let match = Regex.Match(g, "^CN=([^,]*)", RegexOptions.IgnoreCase)
                    where match.Success
                    select new Claim(ClaimTypes.Role, match.Groups[1].Value));

            claims.AddRange(from attribute in config.AdditionalClaimAttributes
                let attr = attributes.TryGetValue(attribute, out var a) ? a : null
                where attr != null
                select new Claim(attribute, attr.StringValue));

            var identity = new ClaimsIdentity(claims, nameof(LdapAuthenticationHandler));

            return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name));
        }
    }
}