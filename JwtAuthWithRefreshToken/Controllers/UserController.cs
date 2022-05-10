using JwtAuthWithRefreshToken.Entities;
using JwtAuthWithRefreshToken.Models;
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

        [AllowAnonymous]
        [HttpPost("refresh")]
        public IActionResult RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if(refreshToken ==null)
                return Unauthorized(new { message = "Invalid Token" });

            var response = _userService.RefreshToken(refreshToken, IpAddress());

            if (response == null)
                return Unauthorized(new { message = "Invalid Token" });

            setTokenCookie(response.RefreshToken);
            return Ok(response);
        }

        [HttpPost("revoke")]
        public ActionResult RevokeToken([FromBody] RevokeTokenRequest model)
        {
            var token = model.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest(new { message = "Token is required" });

            var response = _userService.RevokeToken(token, IpAddress());
            if (!response)
                return NotFound(new { messsage = "Token not found" });

            return Ok(new { messsage ="Token revoked"});

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

        private void setTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7)
            };

            Response.Cookies.Append("refreshToken", token, cookieOptions);  
        }

    }
}
