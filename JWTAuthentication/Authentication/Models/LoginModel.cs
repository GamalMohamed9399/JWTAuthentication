using System.ComponentModel.DataAnnotations;

namespace JWTAuthentication.Authentication.Models
{
    public class LoginModel
    {
        [Required(ErrorMessage = "User Name is requried")]
        public string UserName { get; set; }
        [Required(ErrorMessage = "Password is requried")]
        public string Password { get; set; }
    }
}
