using JwtAuth.Entities;
using JwtAuth.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuth.Helpers
{

    public interface IUserService
    {
        AuthenticateResponse Authenticate(AuthenticateRequest model);
        IEnumerable<User> GetAll();
        User GetById(int id);
    }
    public class UserService : IUserService
    {
        private List<User> _users = new List<User>() {
            new User { FirstName = "firstname1", LastName = "lastname1", Id=1, Password="password1", Username="username1" },
            new User { FirstName = "firstname2", LastName = "lastname2", Id=1, Password="password2", Username="username2" },
            new User { FirstName = "firstname3", LastName = "lastname3", Id=1, Password="password3", Username="username3" },
            new User { FirstName = "firstname4", LastName = "lastname4", Id=1, Password="password4", Username="username4" }
        };

        private readonly AppSettings _appSettings;
        public UserService(IOptions<AppSettings> appSettings)
        {
            _appSettings = appSettings.Value;
        }
       
        public AuthenticateResponse Authenticate(AuthenticateRequest model)
        { 
            var user = _users.FirstOrDefault(x => x.Username == model.Username && x.Password == model.Password);
            if (user == null)
                return null;

            return new AuthenticateResponse() {
               Username = user.Username, Firstname=user.FirstName, Lastname = user.LastName, Id=user.Id, Token = GenerateJwtToken(user)
            };

        }

        public IEnumerable<User> GetAll()
        {
            throw new NotImplementedException();
        }

        public User GetById(int id)
        {
            throw new NotImplementedException();
        }


        private string GenerateJwtToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new[] { new Claim("id", user.Id.ToString()) }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
