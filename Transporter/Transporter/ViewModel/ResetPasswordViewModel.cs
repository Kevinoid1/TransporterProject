using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Transporter.ViewModel
{
    public class ResetPasswordViewModel
    {
        public string Token { get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [DataType(DataType.Password)]
        [Required]
        [Display(Name = "New Password")]
        public string Password { get; set; }

        [Required]
        [Compare("Password", ErrorMessage = "The password and confirmation password don't match.")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; }
    }
}
