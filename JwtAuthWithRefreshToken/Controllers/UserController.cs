using JwtAuthWithRefreshToken.Entities;
using JwtAuthWithRefreshToken.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthWithRefreshToken.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private IUserService _userService;
        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost("auth")]
        public ActionResult Authenticate(AuthenticateRequest model)
        {
            var response = _userService.Authenticate(model);

            if (response == null)
                return BadRequest(new { message = "Username or password is wrong" });

            return Ok(response);

        }

        [Authenticate]
        [HttpGet]
        public ActionResult GetAll()
        {
            var response = _userService.GetAll();
            if(response == null)
                return NotFound();

            return Ok(response);
        }

    }
}
