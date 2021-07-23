using AutoMapper;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Transporter.Services;

namespace Transporter.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IWebHostEnvironment _webHostEnvironment;
        private readonly IMailSender _mailSender;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,
                                 IWebHostEnvironment webHostEnvironment, IMailSender mailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _webHostEnvironment = webHostEnvironment;
            _mailSender = mailSender;
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(CreateAdminVm model)
        {
            if (ModelState.IsValid)
            {
                if(await _userManager.FindByEmailAsync(model.EmailAddress) == null)
                {
                    var user = new IdentityUser
                    {
                        UserName = model.EmailAddress,
                        Email = model.EmailAddress
                    };

                    var result = await _userManager.CreateAsync(user, model.password);
                    if (result.Succeeded)
                    {
                        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        var callbackUrl = Url.Action(nameof(ConfirmEmail), nameof(AccountController),
                                                     new { userId = user.Id, token = token }, protocol: HttpContext.Request.Scheme);
                        var filePath = _webHostEnvironment.WebRootPath + @"\templates\welcome.html";
                        string messageBody;
                        using (var str = new StreamReader(filePath))
                        {
                            messageBody = str.ReadToEnd();
                        }
                        messageBody.Replace("[username]", user.UserName);
                        messageBody.Replace("[callbackUrl]", callbackUrl);
                        await _mailSender.SendEmailAsync($"Welcome {user.UserName}", messageBody, model.EmailAddress);

                        return View("_Layout");

                    }
                    else
                    {
                        ModelState.AddModelError("errors", string.Join("\n", result.Errors.Select(error => error.Description)));
                        return View(model);
                    }
                }
                ModelState.AddModelError("userExists", "User already exists");
                return View(model);

            }
            return View(model);
        }
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (userId == null || token == null)
            {
                return View("Error");
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return View("Error");
            }
            var result = await _userManager.ConfirmEmailAsync(user, token);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, true, false);
                if (result.Succeeded)
                {
                    return RedirectToAction("admin", nameof(HomeController));
                }
                else
                {
                    ModelState.AddModelError("userExists", "User already exists");
                    return View(model);
                }
            }
            return View(model);
        }

        
    }
}
 