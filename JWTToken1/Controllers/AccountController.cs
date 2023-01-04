using JWTToken1.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTToken1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : Controller
    {
        [HttpPost("Authentication")]
        public IActionResult Authentication([FromBody]AuthModel authModel)
        {
            if(string.IsNullOrEmpty(authModel.Username) || string.IsNullOrEmpty(authModel.Password))
                return Unauthorized();
            if(authModel.Username == authModel.Password)
            {
                //authentication is success
              var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes("security@123456789");
                //tokenHandler.CreateToken();
                var tokenDescriptor = new SecurityTokenDescriptor()
                {
                    //subject is nothinhbut payload
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                        new Claim(ClaimTypes.Name, authModel.Username),
                        new Claim(ClaimTypes.Role, "Admin"),
                        new Claim(ClaimTypes.Role,"Murali")

                    }),
                    Expires = DateTime.UtcNow.AddDays(1),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                                       
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var jwttoken = tokenHandler.WriteToken(token);
                return Ok(jwttoken);
            }
            return Unauthorized();
        }
       
       // [HttpGet("GetActionResult")]
        [Authorize(Roles = "Murali")]
        public IActionResult GetActionResult()
        {
            return Ok(new List<string>() { "Murali", "vineeth" });
        }
    }
    
}
