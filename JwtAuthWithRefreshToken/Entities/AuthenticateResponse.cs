using JwtAuthWithRefreshToken.Models;
using System.Text.Json.Serialization;

namespace JwtAuthWithRefreshToken.Entities
{
    public class AuthenticateResponse
    {
        public int Id { get; set; }
        public string Firstname { get; set; }
        public string Lastname { get; set; }
        public string Username { get; set; }
        public string Token { get; set; }

        [JsonIgnore]
        public string RefreshToken { get; set; }
        public AuthenticateResponse(User user, string jwtToken, string refreshToken)
        {
            Id = user.Id;
            Firstname = user.Firstname;
            Lastname = user.Lastname;
            Username = user.Username;
            Token = jwtToken;
            RefreshToken = refreshToken;
        }
    }
}
