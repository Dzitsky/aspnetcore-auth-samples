using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Authorization.Samples.Controllers
{
    public class SampleController : Controller
    {
        [HttpGet("sample")]
        [Authorize(Roles = "appusers")]
        public string Get()
        {
            bool b = User.IsInRole("group2");
            return $"Hello, {User.Identity.Name}";
        }
    }
}