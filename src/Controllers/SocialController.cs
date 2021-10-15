using Authorization.Samples.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Authorization.Samples.Controllers
{
    [Authorize(AuthenticationSchemes = AuthenticationSchemes.Social)]
    public class GoogleController : Controller
    {
        [HttpGet("social_hello")]
        public string AdminHello()
        {
            return $"Hello, {User.Identity!.Name}!";
        }
    }
}