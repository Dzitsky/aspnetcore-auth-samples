using Microsoft.AspNetCore.Authentication;

namespace Authorization.Samples.Authentication
{
    public class LdapAuthenticationOptions : AuthenticationSchemeOptions
    {
        public string Host { get; set; }
        public string BindDn { get; set; }
        public string Password { get; set; }
        public string SearchBase { get; set; }
        public string SearchFilter { get; set; }

        public string[] AdditionalClaimAttributes { get; set; }
    }
}