
using JwtAuthWithRefreshToken.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace JwtAuthWithRefreshToken.Controllers
{
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
    public class AuthenticateAttribute : Attribute, IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var user = (User)context.HttpContext.Items["user"];
            if (user == null)
                context.Result = new JsonResult(new { message = "Unauthorized" }) { StatusCode = StatusCodes.Status401Unauthorized};
        }
    }
}