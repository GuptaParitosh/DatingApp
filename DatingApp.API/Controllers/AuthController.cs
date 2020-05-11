using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _auth;

        public IConfiguration _conf { get; }

        public AuthController(IAuthRepository auth, IConfiguration conf)
        {
            _auth = auth;
            _conf = conf;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserRegistrationDto userRegistrationDto){
            // user validation
            throw new Exception("Chutiya mat kaato");
            if(string.IsNullOrEmpty(userRegistrationDto.Username)){
                return BadRequest("username can't be empty");
            }
            userRegistrationDto.Username = userRegistrationDto.Username.ToLower();

            if(await _auth.UserExists(userRegistrationDto.Username)){
                return BadRequest("User already exists");
            }

            var userToCreate = new User(){
                UserName=userRegistrationDto.Username
            };

            var createdUser= _auth.Register(userToCreate,userRegistrationDto.Password);
            return StatusCode(201);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDto userForLoginDto){
            var userFromRepo = await _auth.Login(userForLoginDto.UserName.ToLower(),userForLoginDto.Password);
            
            if(userFromRepo == null){
                return Unauthorized();
            }
            
            var claims = new []{
                new Claim(ClaimTypes.NameIdentifier, Convert.ToString(userFromRepo.Id)),
                new Claim (ClaimTypes.Name,userFromRepo.UserName)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_conf.GetSection("AppSettings:Token").Value));
            
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var tokenDescriptor = new SecurityTokenDescriptor{
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddMinutes(60),
                SigningCredentials = creds
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return Ok(new{
                token = tokenHandler.WriteToken(token)
            });
        }
    }
}