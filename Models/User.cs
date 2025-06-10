using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace LibraryBackend.Models
{
    public class User
    {
        [Column("id")]
        public int Id { get; set; }

        [Required]
        [Column("login")]
        public string Login { get; set; }

        [Required]
        [Column("password_hash")]
        public string PasswordHash { get; set; }  // Пароль в виде хэша

        [Column("is_admin")]
        public bool IsAdmin { get; set; } = false;  // Роль: админ или обычный пользователь

        [Column("refresh_token")]
        public string? RefreshToken { get; set; }

        [Column("refresh_token_expiry_time")]
        public DateTime? RefreshTokenExpiryTime { get; set; }
    }
}
