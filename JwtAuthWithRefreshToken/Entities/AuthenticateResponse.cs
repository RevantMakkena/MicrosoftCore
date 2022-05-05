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
    }
}
