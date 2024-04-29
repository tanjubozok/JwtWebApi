namespace JwtWebApiDemo.Models;

public class UserModel
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string EmailAddress { get; set; } = string.Empty;
    public DateTime DateOfJoing { get; set; } = DateTime.Now;
}
