using System.ComponentModel.DataAnnotations;

namespace LibraryBackend.Data
{
    public class RegisterDto
    {
        [Required]
        public string Login { get; set; }

        [Required]
        [MinLength(6)]
        public string Password { get; set; }
    }

    public class LoginDto
    {
        [Required]
        public string Login { get; set; }

        [Required]
        public string Password { get; set; }
    }

    namespace LibraryBackend.Data
    {
        public class AuthResponseDto
        {
            public string Token { get; set; } 
            public string Login { get; set; }
            public string Role { get; set; }
        }
    }
}
