using JwtAuthWithRefreshToken.Entities;
using JwtAuthWithRefreshToken.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthWithRefreshToken.Controllers
{
    [Authorize]
    [Route("[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private IUserService _userService;
        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        [AllowAnonymous]
        [HttpPost("auth")]
        public ActionResult Authenticate([FromBody]AuthenticateRequest model)
        {
            var response = _userService.Authenticate(model, IpAddress());

            if (response == null)
                return BadRequest(new { message = "Username or password is wrong" });

            return Ok(response);

        }

        [HttpGet]
        public ActionResult GetAll()
        {
            var response = _userService.GetAll();
            if(response == null)
                return NotFound();

            return Ok(response);
        }


        private string IpAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress?.MapToIPv4().ToString() ?? "";
        }

    }
}
