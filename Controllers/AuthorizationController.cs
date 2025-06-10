using LibraryBackend.Data;
using LibraryBackend.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace LibraryBackend.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthorizationController : ControllerBase
    {
        private readonly LibraryContext _context;
        private readonly IConfiguration _config;
        private readonly ILogger<AuthorizationController> _logger;

        public AuthorizationController(
            LibraryContext context,
            IConfiguration config,
            ILogger<AuthorizationController> logger)
        {
            _context = context;
            _config = config;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto dto)
        {
            try
            {
                if (await _context.Users.AnyAsync(u => u.Login == dto.Login))
                    return BadRequest(new { Message = "Пользователь с таким логином уже существует" });

                var user = new User
                {
                    Login = dto.Login,
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password),
                    IsAdmin = false,
                    RefreshToken = null,
                    RefreshTokenExpiryTime = null
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                return Ok(new { Message = "Регистрация успешно завершена" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ошибка при регистрации пользователя");
                return StatusCode(500, new { Message = "Внутренняя ошибка сервера" });
            }
        }

        [HttpPost("login")]
        public async Task<ActionResult<AuthResponseDto>> Login([FromBody] LoginDto dto)
        {
            try
            {
                var user = await _context.Users
                    .FirstOrDefaultAsync(u => u.Login == dto.Login);

                if (user == null || !BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash))
                {
                    _logger.LogWarning("Неудачная попытка входа для пользователя: {Login}", dto.Login);
                    return Unauthorized(new { Message = "Неверный логин или пароль" });
                }

                var accessToken = GenerateJwtToken(user, false);
                var refreshToken = GenerateJwtToken(user, true);

                user.RefreshToken = refreshToken;
                user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(_config.GetValue<int>("Jwt:RefreshTokenExpiryInDays"));
                await _context.SaveChangesAsync();

                SetTokensInCookies(accessToken, refreshToken);

                return Ok(new AuthResponseDto
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    Login = user.Login,
                    Role = user.IsAdmin ? "Admin" : "User"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ошибка при входе пользователя");
                return StatusCode(500, new { Message = "Внутренняя ошибка сервера" });
            }
        }

        [HttpPost("refresh")]
        public async Task<ActionResult<AuthResponseDto>> RefreshToken()
        {
            try
            {
                var refreshToken = Request.Cookies["refreshToken"];
                if (string.IsNullOrEmpty(refreshToken))
                    return Unauthorized(new { Message = "Refresh token отсутствует" });

                var principal = GetPrincipalFromToken(refreshToken, true);
                var loginClaim = principal?.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
                if (loginClaim == null)
                    return Unauthorized(new { Message = "Неверный refresh token" });

                var user = await _context.Users
                    .FirstOrDefaultAsync(u => u.Login == loginClaim.Value);

                if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
                    return Unauthorized(new { Message = "Неверный refresh token или срок действия истёк" });

                var newAccessToken = GenerateJwtToken(user, false);
                var newRefreshToken = GenerateJwtToken(user, true);

                user.RefreshToken = newRefreshToken;
                user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(_config.GetValue<int>("Jwt:RefreshTokenExpiryInDays"));
                await _context.SaveChangesAsync();

                SetTokensInCookies(newAccessToken, newRefreshToken);

                return Ok(new AuthResponseDto
                {
                    AccessToken = newAccessToken,
                    RefreshToken = newRefreshToken,
                    Login = user.Login,
                    Role = user.IsAdmin ? "Admin" : "User"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ошибка при обновлении токена");
                return StatusCode(500, new { Message = "Внутренняя ошибка сервера" });
            }
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (!string.IsNullOrEmpty(refreshToken))
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.RefreshToken == refreshToken);
                if (user != null)
                {
                    user.RefreshToken = null;
                    user.RefreshTokenExpiryTime = null;
                    await _context.SaveChangesAsync();
                }
            }

            Response.Cookies.Delete("jwt", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Path = "/"
            });

            Response.Cookies.Delete("refreshToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Path = "/"
            });

            return Ok(new { Message = "Выход выполнен успешно" });
        }

        [HttpGet("check")]
        public async Task<ActionResult<AuthResponseDto>> CheckAuth()
        {
            try
            {
                var jwt = Request.Cookies["jwt"];
                if (string.IsNullOrEmpty(jwt))
                    return Unauthorized();

                var tokenHandler = new JwtSecurityTokenHandler();
                var token = tokenHandler.ReadJwtToken(jwt);

                var loginClaim = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
                if (loginClaim == null)
                    return Unauthorized();

                var user = await _context.Users
                    .FirstOrDefaultAsync(u => u.Login == loginClaim.Value);

                if (user == null)
                    return Unauthorized();

                return Ok(new AuthResponseDto
                {
                    AccessToken = jwt,
                    Login = user.Login,
                    Role = user.IsAdmin ? "Admin" : "User"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ошибка проверки авторизации");
                return Unauthorized();
            }
        }

        private string GenerateJwtToken(User user, bool isRefreshToken)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Login),
                new Claim(ClaimTypes.Role, user.IsAdmin ? "Admin" : "User")
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var expires = isRefreshToken
                ? DateTime.UtcNow.AddDays(_config.GetValue<int>("Jwt:RefreshTokenExpiryInDays"))
                : DateTime.UtcNow.AddMinutes(_config.GetValue<int>("Jwt:ExpiryInMinutes"));

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private ClaimsPrincipal? GetPrincipalFromToken(string token, bool isRefreshToken)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = _config["Jwt:Issuer"],
                ValidateAudience = true,
                ValidAudience = _config["Jwt:Audience"],
                ValidateLifetime = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"])),
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.Zero
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
                if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                    !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                    return null;

                return principal;
            }
            catch
            {
                return null;
            }
        }

        private void SetTokensInCookies(string accessToken, string refreshToken)
        {
            var accessTokenCookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Expires = DateTime.UtcNow.AddMinutes(_config.GetValue<int>("Jwt:ExpiryInMinutes")),
                Path = "/"
            };

            var refreshTokenCookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Expires = DateTime.UtcNow.AddDays(_config.GetValue<int>("Jwt:RefreshTokenExpiryInDays")),
                Path = "/"
            };

            Response.Cookies.Append("jwt", accessToken, accessTokenCookieOptions);
            Response.Cookies.Append("refreshToken", refreshToken, refreshTokenCookieOptions);
        }
    }

    public class RegisterDto
    {
        public string Login { get; set; }
        public string Password { get; set; }
    }

    public class LoginDto
    {
        public string Login { get; set; }
        public string Password { get; set; }
    }

    public class AuthResponseDto
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public string Login { get; set; }
        public string Role { get; set; }
    }
}