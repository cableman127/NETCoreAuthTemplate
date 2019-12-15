using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace NETCoreAuthAPI.Dtos
{

    public class ResetPasswordDto
    {
        [Required(ErrorMessage = "Email is a Required field.")]
        [StringLength(50, ErrorMessage = "Email cannot be longer than 50 characters.")]
        [DataType(DataType.EmailAddress)]
        [EmailAddress]
        [RegularExpression(@"^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$",
        ErrorMessage = "Email is required and must be properly formatted.")]
        public string Email { get; set; }
        [Required(ErrorMessage = "Password is a Required field.")]
        [StringLength(20, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        public string Code { get; set; }

        //public string ReCaptchaToken { get; set; }
    }
}

