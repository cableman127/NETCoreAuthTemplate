using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Runtime.Serialization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace NETCoreAuthAPI.Models.AccountModels {

    public class ApplicationUser : IdentityUser
    {

        [Required(ErrorMessage = "Email is a Required field.")]
        [StringLength(50, ErrorMessage = "Email cannot be longer than 50 characters.")]
        [DataType(DataType.EmailAddress)]
        [EmailAddress]
        [RegularExpression(@"^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$",
        ErrorMessage = "Email is required and must be properly formatted.")]
        public override string Email { get; set; }

        public string refreshToken { get; set; }

        [DataType(DataType.DateTime)]
        public DateTime? UpdatedOn { get; set; }

        [StringLength(50)]
        [DataType(DataType.Text)]
        public string UpdatedBy { get; set; }

        [DataType(DataType.DateTime)]
        public DateTime? CreatedOn { get; set; }

        [StringLength(50)]
        [DataType(DataType.Text)]
        public string CreatedBy { get; set; }

        [DataType(DataType.DateTime)]
        public DateTime? LastLoginDate { get; set; }

    }
}
