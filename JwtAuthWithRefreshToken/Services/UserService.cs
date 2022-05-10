using JwtAuthWithRefreshToken.Entities;
using JwtAuthWithRefreshToken.Helpers;
using JwtAuthWithRefreshToken.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuthWithRefreshToken.Services
{

    public interface IUserService
    {
        AuthenticateResponse Authenticate(AuthenticateRequest request, string ipAddress);
        AuthenticateResponse RefreshToken(string token, string ipAddress);
        bool RevokeToken(string token, string ipAddress);
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
        private DataContext _dataContext;
        public UserService(IOptions<AppSettings> appSettings, DataContext context)
        {
            _appSettings = appSettings.Value;
            _dataContext = context;
        }

        public AuthenticateResponse Authenticate(AuthenticateRequest request, string ipAddress)
        {
            //var user = _users.FirstOrDefault(x => x.Username == request.username && x.Password == request.password);
            var user = _dataContext.Users.SingleOrDefault(x => x.Username == request.username && x.Password == request.password);

            if (user == null)
                return null;

            var token = CreateJwtToken(user);
            var refreshToken = GenerateRefreshToken(ipAddress);

            //Save Refresh Token 
            user.RefreshTokens.Add(refreshToken);
            _dataContext.Update(user);
            _dataContext.SaveChanges();

            return new AuthenticateResponse(user, token, refreshToken.Token);
        }

        public AuthenticateResponse RefreshToken(string token, string ipAddress)
        {
            var user = _dataContext.Users.SingleOrDefault(x => x.RefreshTokens.Any(t => t.Token == token));
            if (user == null) return null;

            var refreshToken = user.RefreshTokens.Single(t => t.Token == token);
            if (!refreshToken.IsActive) return null;

            var newRefreshToken = GenerateRefreshToken(ipAddress);
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;
            refreshToken.ReplacedByToken = newRefreshToken.Token;
            user.RefreshTokens.Add(newRefreshToken);
            _dataContext.Update(user);
            _dataContext.SaveChanges();

            //Generate new JWT 
            var jwtToken = CreateJwtToken(user);
            return new AuthenticateResponse(user, jwtToken, newRefreshToken.Token);
        }

        public bool RevokeToken(string token, string ipAddress)
        {
            var user = _dataContext.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));
            if(user == null) return false;

            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);
            if(!refreshToken.IsActive) return false;

            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;
            _dataContext.Update(user);
            _dataContext.SaveChanges();

            return true;
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
                Subject = new System.Security.Claims.ClaimsIdentity(new[] {
                    new Claim(ClaimTypes.Name, user.Id.ToString()) 
                
                }),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)

            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);

        }

        private RefreshToken GenerateRefreshToken(string ipAddress)
        {
            using(var rngCryptoServiceProvider = new RNGCryptoServiceProvider())
            {
                var randomBytes = new byte[64];
                rngCryptoServiceProvider.GetBytes(randomBytes);
                return new RefreshToken
                {
                    Token = Convert.ToBase64String(randomBytes),
                    Expires = DateTime.Now.AddDays(7),
                    Created = DateTime.Now,
                    CreatedByIp = ipAddress,
                    ReplacedByToken = String.Empty,
                    RevokedByIp = String.Empty
                };
            }
        }
    }
}
