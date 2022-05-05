using JwtAuthWithRefreshToken.Entities;
using JwtAuthWithRefreshToken.Helpers;
using JwtAuthWithRefreshToken.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthWithRefreshToken.Services
{

    public interface IUserService
    {
        AuthenticateResponse Authenticate(AuthenticateRequest request);
        IEnumerable<User> GetAll();
        User? GetById(int id);    
    }

    public class UserService : IUserService
    {
        private List<User> _users = new List<User>() {
            new User { Firstname = "firstname1", Lastname = "lastname1", Id=1, Password="password1", Username="username1" },
            new User { Firstname = "firstname2", Lastname = "lastname2", Id=1, Password="password2", Username="username2" },
            new User { Firstname = "firstname3", Lastname = "lastname3", Id=1, Password="password3", Username="username3" },
            new User { Firstname = "firstname4", Lastname = "lastname4", Id=1, Password="password4", Username="username4" }
        };

        private readonly AppSettings _appSettings;
        public UserService(IOptions<AppSettings> appSettings)
        {
            _appSettings = appSettings.Value;
        }

        public AuthenticateResponse Authenticate(AuthenticateRequest request)
        {
            var user = _users.FirstOrDefault(x => x.Username == request.username && x.Password == request.password);  
            if (user == null)
                return null;

            var token = CreateJwtToken(user);
            return new AuthenticateResponse() { Firstname = user.Firstname, Lastname = user.Lastname, Token = token, Username = user.Username, Id=user.Id };
        }

        public IEnumerable<User> GetAll()
        {
            return _users;
        }

        public User? GetById(int id)
        {
            return _users.FirstOrDefault(x => x.Id == id);
        }

        private string CreateJwtToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Expires = DateTime.Now.AddDays(7),
                Subject = new System.Security.Claims.ClaimsIdentity(new[] { new Claim("id", user.Id.ToString()) }),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)

            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);

        }
    }
}
