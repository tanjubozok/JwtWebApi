using JwtWebApiDemo.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace JwtWebApiDemo.Controllers;

[Route("api/[controller]")]
[ApiController]
public class LoginController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public LoginController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    [AllowAnonymous]
    [HttpPost]
    public IActionResult Login([FromBody] UserModel login)
    {
        IActionResult response = Unauthorized();
        var user = AuthenticateUser(login);

        if (user != null)
        {
            var tokenString = GenerateJSONWebToken(user);
            response = Ok(new
            {
                token = tokenString
            });
        }

        return response;
    }

    private string GenerateJSONWebToken(UserModel userInfo)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            _configuration["Jwt:Issuer"],
            _configuration["Jwt:Issuer"],
            null,
            expires: DateTime.Now.AddMinutes(120),
            signingCredentials: credentials
            );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private UserModel AuthenticateUser(UserModel login)
    {
        UserModel user = null;

        if (login.Username == "tanjubozok")
        {
            user = new UserModel
            {
                Username = "tanjubozok",
                EmailAddress = "admin@localhost"
            };
        }
        return user!;
    }
}

