using System.Linq;
using Authorization.Samples.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Authorization.Samples.Controllers
{
    [Authorize(AuthenticationSchemes = AuthenticationSchemes.AppJwt)]
    public class JwtController : Controller
    {
        [HttpGet("jwt_hello")]
        public string AdminHello()
        {
            return $"Hello, {User.Claims.Single(c => c.Type == "name").Value}!";
        }
    }
}