using JWTTokenAuthenticaton.Data;
using JWTTokenAuthenticaton.Models.ViewModels;
using JWTTokenAuthenticaton.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using System.Security.Cryptography;


namespace JWTTokenAuthenticaton.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
         private readonly ApplicationDbContext _db;
         SignInManager<ApplicationUser> _signInManager;
         UserManager<ApplicationUser> _userManager;
         RoleManager<IdentityRole> _roleManager;
         private readonly IConfiguration _configuration;

         public AccountController(ApplicationDbContext db,
         SignInManager<ApplicationUser> signInManager,
         UserManager<ApplicationUser> userManager,
         RoleManager<IdentityRole> roleManager,
         IConfiguration configuration)
         {
             this._db = db;
             _signInManager = signInManager;
             _userManager = userManager;
             _roleManager = roleManager;
             _configuration = configuration;
         }

        [Authorize]
        [HttpGet("Index")]
         public IActionResult Index( )
         {
            
             return Ok("hghjghjghjghjghj ");
         }
       
        [HttpPost("login")]
        
        public async Task<IActionResult> login(LoginModel loginModel)    
        {
                var responsemodel = new LoginResponse();

            if (ModelState.IsValid)               
            {
                var result = await _signInManager.PasswordSignInAsync(loginModel.Email, loginModel.Password, false, true /*lockoutOnFailure: true*/);                  
                if (result.Succeeded)                
                {                
                    var user = await _userManager.FindByNameAsync(loginModel.Email);  
                    var authClaims = new List<Claim>
                    
                    {                         
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                       
                        new Claim("Email" , user.Email.ToString()),
                    };
                    var token = GetToken(authClaims);
                    responsemodel.Token = new JwtSecurityTokenHandler().WriteToken(token);
                    responsemodel.RefreshToken =  this.GenerateRefreshToken();
                    responsemodel.Status = "Success";
                    responsemodel.Message = "Login Success";
                    user.RefreshToken = responsemodel.RefreshToken;
                    user.RefreshTokenExpiry = DateTime.Now.AddHours(12);
                    await _userManager.UpdateAsync(user);
                }              
                if (result.IsLockedOut)
                {
                    responsemodel.Status = "Error";
                    responsemodel.Message = "Your Account is locked out";
                }               
            }           
            ModelState.AddModelError("", "Invalid Login attempt");           
            return Ok(responsemodel);   
        }
        
        [HttpPost("Register")]       
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterModel registerModel)
            {
                if (ModelState.IsValid)
                {
                    var user = new ApplicationUser
                    {
                        UserName = registerModel.EmailAddress,
                        Email = registerModel.EmailAddress,
                        NormalizedUserName = registerModel.EmailAddress.ToUpper(),
                        NormalizedEmail = registerModel.EmailAddress.ToUpper(),
                        Name = registerModel.RoleName,
                    };

                    var result = await _userManager.CreateAsync(user, registerModel.Password);
                    if (result.Succeeded)
                    {
                        var role = await _roleManager.FindByNameAsync("User");
                        await _userManager.AddToRoleAsync(user, registerModel.RoleName);
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        return RedirectToAction("Index", "Account");
                    }
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                }
                return Ok();
            }
   
        private JwtSecurityToken GetToken(List<Claim> authClaims)        
        {     
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Key"]));
         
            var token = new JwtSecurityToken
                (
            
                 issuer: _configuration["JWT:ValidIssuer"],
                
                 audience: _configuration["JWT:ValidAudience"],
                
                 expires: DateTime.Now.AddSeconds(10),
                
                 claims: authClaims,
                 
                 signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)           
                ); 
            
            return token;           
        }
        private string GenerateRefreshToken()
        {
            var random = new byte[64];

            using (var nbrGenerate = RandomNumberGenerator.Create())
            {
                
                nbrGenerate.GetBytes(random);
            }
            return Convert.ToBase64String(random);
        }
       
        [HttpPost("refreshToken")]
        public async Task<LoginResponse> refreshToken(string refreshToken)
        {
            var _refreshToken = _userManager.Users.SingleOrDefault(m => m.RefreshToken == refreshToken);
            var response = new LoginResponse();
            var login = new LoginModel();
            if (_refreshToken == null)
            {
                NotFound("Refresh token not found");
            }
            else
            {
                var userclaim = new[] { new Claim(ClaimTypes.Email, _refreshToken.Email) };
                var identityUser = await _userManager.FindByEmailAsync(_refreshToken.Email);
                if (identityUser is null || identityUser.RefreshToken != refreshToken ||identityUser.RefreshTokenExpiry > DateTime.UtcNow)
                {
                    response = response;
                }
            }
            var authClaims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("Email" , _refreshToken.Email.ToString()),
            };
            var token = GetToken(authClaims);
            response.Token = new JwtSecurityTokenHandler().WriteToken(token);
            response.RefreshToken = this.GenerateRefreshToken();
            response.Status = "Success";
            response.Message = "Login Success";
           _refreshToken.RefreshToken = response.RefreshToken;
           _refreshToken.RefreshTokenExpiry = DateTime.Now.AddHours(12);
           await _userManager.UpdateAsync(_refreshToken);
           return response;
        }

        [HttpPost("logout")]
        [ValidateAntiForgeryToken]        
        public async Task<IActionResult> logout()       
        {       
            await _signInManager.SignOutAsync();           
            return RedirectToAction("Login", "Account");            
        }
    }  
}






