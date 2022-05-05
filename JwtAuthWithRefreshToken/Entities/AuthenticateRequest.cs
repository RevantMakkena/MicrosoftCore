using System.ComponentModel.DataAnnotations;

namespace JwtAuthWithRefreshToken.Entities
{
    public class AuthenticateRequest
    {
        [Required]
        public string username { get; set; }

        [Required]
        public string password { get; set; }
    }
}
