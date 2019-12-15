using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace NETCoreAuthAPI.Dtos
{
    public class EmailDto
    {
        [Required(ErrorMessage = "Email is a Required field.")]
        [StringLength(50, ErrorMessage = "Email cannot be longer than 50 characters.")]
        [DataType(DataType.EmailAddress)]
        [EmailAddress]
        [RegularExpression(@"^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$",
        ErrorMessage = "Email is required and must be properly formatted.")]
        public string Email { get; set; }
    }
}
