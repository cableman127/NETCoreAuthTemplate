using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NETCoreAuthAPI.Dtos;
using NETCoreAuthAPI.Helpers;
using NETCoreAuthAPI.Models.AccountModels;
using NETCoreAuthAPI.Security;
using NETCoreAuthAPI.Services;

namespace NETCoreAuthAPI.Controllers
{
    [ApiController]
    [Authorize]
    [Route("[controller]")]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private EmailSender _emailSender;
        private readonly ILogger _logger;
        private readonly TokenAuthOption _tokenOptions;
        private readonly AppSettings _appSettings;

        public AccountController(
             UserManager<ApplicationUser> userManager,
             SignInManager<ApplicationUser> signInManager,
             RoleManager<IdentityRole> roleManager,
             ILoggerFactory loggerFactory,
             IOptions<TokenAuthOption> tokenOptions,
             IOptions<AppSettings> appSettingsAccessor)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _logger = loggerFactory.CreateLogger<AccountController>();
            _tokenOptions = tokenOptions.Value;
            _appSettings = appSettingsAccessor.Value;
            _emailSender = new EmailSender(appSettingsAccessor);

        }

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody]UserDto model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new RequestResult
                {
                    State = RequestState.Failed,
                    Msg = "Error: " + string.Join(" ", ModelState.Values.SelectMany(x => x.Errors).Select(x => x.ErrorMessage)),
                });
            }

            var user = new ApplicationUser { UserName = model.Email, Email = model.Email, LockoutEnabled = true };

            var result = await _userManager.CreateAsync(user, model.Password).ConfigureAwait(false);

            string role = "Basic User";

            if (result.Succeeded)
            {
                if (await _roleManager.FindByNameAsync(role).ConfigureAwait(false) == null)
                {
                    await _roleManager.CreateAsync(new IdentityRole(role)).ConfigureAwait(false);
                }
                await _userManager.AddToRoleAsync(user, role).ConfigureAwait(false);
                await _userManager.AddClaimAsync(user, new Claim("userName", user.UserName)).ConfigureAwait(false);
                await _userManager.AddClaimAsync(user, new Claim("email", user.Email)).ConfigureAwait(false);
                await _userManager.AddClaimAsync(user, new Claim("role", role)).ConfigureAwait(false);
                await _userManager.AddClaimAsync(user, new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName)).ConfigureAwait(false);

                // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
                // Send an email with this link
                string code = await _userManager.GenerateEmailConfirmationTokenAsync(user).ConfigureAwait(false);

                var callbackUrl = Url.Action("ConfirmEmail", "Account",
                new { userId = user.Id, code },
                protocol: HttpContext.Request.Scheme);

                await _emailSender.SendEmailAsync(
                    user.Email,
                    "**Do Not Reply** NetCoreAuth Email Verification",
                    "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>").ConfigureAwait(false);


                return Ok(new RequestResult
                {
                    State = RequestState.Success,
                    Msg = "Registration succeeded. Check your email for verification"
                });
            }
            else
            {
                return BadRequest(new RequestResult
                {
                    State = RequestState.Failed,
                    Msg = "Error: " +string.Join(" ", result.Errors.Select(x => x.Description)),
                    //Msg = result.Errors.First().Description,
                });
            }
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserDto model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email).ConfigureAwait(false);
                if (user != null)
                {
                    if (!_userManager.IsEmailConfirmedAsync
                         (user).Result)
                    {
                        return BadRequest(new RequestResult
                        {
                            State = RequestState.Failed,
                            Msg = "Email not confirmed!"
                        });
                    }
                }
                else
                {
                    return BadRequest(new RequestResult
                    {
                        State = RequestState.Failed,
                        Msg = "Error: Email not found!"
                    });
                }

                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, isPersistent: model.isPersistent, lockoutOnFailure: false).ConfigureAwait(false);

                if (result.Succeeded)
                {
                    var claims = _userManager.GetClaimsAsync(user);
                    var id = new ClaimsIdentity(claims.Result);

                    var requestAt = DateTime.Now;
                    var expiresIn = requestAt + TokenAuthOption.Lifetime;
                    var token = GenerateToken(expiresIn, id);
                    var refreshToken = GenerateRefreshToken();
                    user.LastLoginDate = requestAt;
                    user.refreshToken = refreshToken;
                    await _userManager.UpdateAsync(user).ConfigureAwait(false);


                    return Ok(new RequestResult
                    {
                        State = RequestState.Success,
                        Msg = "Login Successful!",
                        Data = new
                        {
                            requestAt,
                            expiresIn = TokenAuthOption.Lifetime.TotalSeconds,
                            tokenType = TokenAuthOption.TokenType,
                            accessToken = token,
                            refreshToken,
                        }
                    });
                }
                else
                {
                    user.AccessFailedCount++;
                    await _userManager.UpdateAsync(user).ConfigureAwait(false);

                    if (user.AccessFailedCount > 8 | result.IsLockedOut)
                    {
                        return BadRequest(new RequestResult
                        {
                            State = RequestState.Failed,
                            Msg = "Error: Account Login failed more than 8 times. Account is locked. Please wait until it is unlocked!"
                        });
                    }

                    return BadRequest(new RequestResult
                    {
                        State = RequestState.Failed,
                        Msg = "Error: Password invalid for that email address!",
                    });
                }
            }
            else
            {
                return BadRequest(new RequestResult
                {
                    State = RequestState.Failed,
                    Msg = "Error: " + string.Join(" ", ModelState.Values.SelectMany(x => x.Errors).Select(x => x.ErrorMessage)),
                });
            }
        }

        private string GenerateToken(DateTime expires, ClaimsIdentity claims)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_tokenOptions.Key));
            var utcNow = DateTime.UtcNow;
            var handler = new JwtSecurityTokenHandler();
            var signingCreds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var securityToken = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = _tokenOptions.Issuer,
                Audience = _tokenOptions.Audience,
                SigningCredentials = signingCreds,
                Subject = claims,
                NotBefore = utcNow,
                Expires = expires
            });

            return handler.WriteToken(securityToken);
        }

        public static string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true, //you might want to validate the audience and issuer depending on your use case
                ValidateIssuer = true,
                ValidAudience = _tokenOptions.Audience,
                ValidIssuer = _tokenOptions.Issuer,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_tokenOptions.Key)),
                ValidateLifetime = false //here we are saying that we don't care about the token's expiration date
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }


        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshAsync(string token, string refreshToken)
        {

            var principal = GetPrincipalFromExpiredToken(token);
            var username = principal.Identity.Name; //this is mapped to the Name claim by default

            var user = await _userManager.FindByNameAsync(username).ConfigureAwait(false);

            if (user == null)
            {
                return BadRequest(new RequestResult
                {
                    State = RequestState.Failed,
                    Msg = "Error: Could not find user to refresh token!"
                });
            }
            var savedRefreshToken = user.refreshToken;//GetRefreshToken(username); //retrieve the refresh token from a data store
            
            if (savedRefreshToken != refreshToken)
            {
                return BadRequest(new RequestResult
                {
                    State = RequestState.Failed,
                    Msg = "Error: Failed to refresh token!"
                });
                throw new SecurityTokenException("Invalid refresh token");
            }
                
            var requestAt = DateTime.Now;
            var expiresIn = requestAt + TokenAuthOption.Lifetime;
            var newJwtToken = GenerateToken(expiresIn, new ClaimsIdentity(principal.Claims));
            var newRefreshToken = GenerateRefreshToken();

            user.refreshToken = newRefreshToken;

            var result = await _userManager.UpdateAsync(user).ConfigureAwait(false);

            if (!result.Succeeded)
            {
                return BadRequest(new RequestResult
                {
                    State = RequestState.Failed,
                    Msg = "Error: " + string.Join(" ", result.Errors.Select(x => x.Description)),
                });
            }

            return Ok(new RequestResult
            {
                State = RequestState.Success,
                Msg = "Token refreshed!",
                Data = new
                {
                    requestAt,
                    expiresIn = TokenAuthOption.Lifetime.TotalSeconds,
                    tokenType = TokenAuthOption.TokenType,
                    accessToken = newJwtToken,
                    refreshToken = newRefreshToken,
                }
            });
        }


        [HttpGet("confirm-email/{userId}/{code}")]
        [AllowAnonymous]
        public async Task<ContentResult> ConfirmEmail(string userId, string code)
        {
            ApplicationUser user = await _userManager.FindByIdAsync(userId).ConfigureAwait(false);
            string decodedCode = DecodeUrlString(code);
            IdentityResult result = await _userManager.ConfirmEmailAsync(user, decodedCode).ConfigureAwait(false);

            if (result.Succeeded)
            {

                return new ContentResult
                {
                    ContentType = "text/html",
                    StatusCode = (int)HttpStatusCode.OK,
                    Content = "<html><body>Email Verification Successful!</body></html>"
                };
            }
            else
            {
                return new ContentResult
                {
                    ContentType = "text/html",
                    StatusCode = (int)HttpStatusCode.PreconditionFailed,
                    Content = "<html><body>Invalid/Expired Email Token. Please retry Email Verification!</body></html>"
                };
            }
        }


        [HttpPost]
        [Route("request-reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> RequestResetPassword([FromBody] EmailDto model)
        {
            if (ModelState.IsValid)
            {

                bool isEmail = Regex.IsMatch(model.Email, @"\A(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\Z", RegexOptions.IgnoreCase);

                if (isEmail)
                {
                    ApplicationUser user = await _userManager.FindByEmailAsync(model.Email).ConfigureAwait(false);

                    if (user != null)
                    {
                        // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
                        // Send an email with this link
                        string code = await _userManager.GeneratePasswordResetTokenAsync(user).ConfigureAwait(false);

                        var callbackUrl = Url.Action("ResetPassword", "Account",
                        new { userId = user.Id, code },
                        protocol: HttpContext.Request.Scheme);

                        await _emailSender.SendEmailAsync(
                            user.Email,
                            "**Do Not Reply** NetAuthCore Password Reset Code",
                            "Your password reset code is: " + code + ". \n Please go to <a href=\"" + "https://localhost:4001/#/reset-password" + "\">NetCoreAuth</a> and reset your password").ConfigureAwait(false);

                        return Ok(new RequestResult
                        {
                            State = RequestState.Success,
                            Msg = "Email sent for password reset request. Please check your email!"
                        });
                    }


                    return BadRequest(new RequestResult
                    {
                        State = RequestState.Failed,
                        Msg = "Error: Email not found!"
                    });


                }
                else
                {
                    return BadRequest(new RequestResult
                    {
                        State = RequestState.Failed,
                        Msg = "Error: Email not valid!"
                    });
                }
            }
            else
            {
                return BadRequest(new RequestResult
                {
                    State = RequestState.Failed,
                    Msg = "Error: " + string.Join(" ", ModelState.Values.SelectMany(x => x.Errors).Select(x => x.ErrorMessage)),
                });
            }
        }


        [HttpPost]
        [Route("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto model)
        {
            if (ModelState.IsValid)
            {

                bool isEmail = Regex.IsMatch(model.Email, @"\A(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\Z", RegexOptions.IgnoreCase);

                if (isEmail)
                {
                    ApplicationUser user = await _userManager.FindByEmailAsync(model.Email).ConfigureAwait(false);

                    if (user != null)
                    {
                        // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
                        // Send an email with this link
                        IdentityResult result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password).ConfigureAwait(false);

                        if (result.Succeeded)
                        {

                            await _emailSender.SendEmailAsync(
                            user.Email,
                            "**Do Not Reply** NetAuthCore Password has been changed!",
                            "Your NetAuthCore password has been changed!").ConfigureAwait(false);

                            return Ok(new RequestResult
                            {
                                State = RequestState.Success,
                                Msg = "Password has been successfully reset! Please login using the new password."
                            });
                        }
                        else
                        {
                            return BadRequest(new RequestResult
                            {
                                State = RequestState.Failed,
                                Msg = result.Errors.ToString()
                            });
                        }
                    }

                    return BadRequest(new RequestResult
                    {
                        State = RequestState.Failed,
                        Msg = "Error: User not found!"
                    });
                }
                else
                {
                    return BadRequest(new RequestResult
                    {
                        State = RequestState.Failed,
                        Msg = "Error: Email not valid!"
                    });
                }
            }
            else
            {
                return BadRequest(new RequestResult
                {
                    State = RequestState.Failed,
                    Msg = "Error: " + string.Join(" ", ModelState.Values.SelectMany(x => x.Errors).Select(x => x.ErrorMessage)),
                });
            }
        }

        [HttpGet]
        [Route("test")]
        public IActionResult TestAuthTokenHere()
        {
            return Ok(new RequestResult
            {
                State = RequestState.Success,
                Msg = "JWT Bearer Token Works!."
            });
        }


        private static string DecodeUrlString(string url)
        {
            string newUrl;
            while ((newUrl = Uri.UnescapeDataString(url)) != url)
                url = newUrl;
            return newUrl;
        }
    }
}