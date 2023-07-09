using Microsoft.EntityFrameworkCore.Storage.ValueConversion.Internal;
using System.ComponentModel.DataAnnotations;

namespace JWTAuthentication.Authentication.Models
{
    public class RegistgerModel
    {
        [Required(ErrorMessage ="User Name is requried")]
        public string UserName { get;set; }
        [EmailAddress]
        [Required(ErrorMessage ="Email is requried")]
        public string Email { get;set; }
        [Required(ErrorMessage ="Password is requried")]
        public string Password { get; set; }
    }
}
