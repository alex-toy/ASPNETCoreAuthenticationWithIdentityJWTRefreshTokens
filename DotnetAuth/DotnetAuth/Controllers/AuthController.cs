using DotnetAuth.Dtos;
using DotnetAuth.Services.Authentication;
using DotnetAuth.Services.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotnetAuth.Controllers;

public class AuthController : ControllerBase
{
    private readonly IUserService _userService;
    private readonly IAuthService _authService;

    public AuthController(IUserService userService, IAuthService authService)
    {
        _userService = userService;
        _authService = authService;
    }

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] RegistrationDto request)
    {
        var response = await _authService.RegisterAsync(request);
        return Ok(response);
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginDto request)
    {
        var response = await _authService.LoginAsync(request);
        return Ok(response);
    }

    [HttpGet("user/{id}")]
    [Authorize]
    public async Task<IActionResult> GetById(Guid id)
    {
        var response = await _userService.GetByIdAsync(id);
        return Ok(response);
    }

    [HttpPost("refresh-token")]
    [Authorize]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto request)
    {
        var response = await _authService.RefreshTokenAsync(request);
        return Ok(response);
    }

    [HttpPost("revoke-refresh-token")]
    [Authorize]
    public async Task<IActionResult> RevokeRefreshToken([FromBody] RefreshTokenDto request)
    {
        RevokeRefreshTokenDto? response = await _authService.RevokeRefreshToken(request);
        if (response is not null && response.Message == "Refresh token revoked successfully")
        {
            return Ok(response);
        }
        return BadRequest(response);
    }

    [HttpGet("current-user")]
    [Authorize]
    public async Task<IActionResult> GetCurrentUser()
    {
        UserDto response = await _userService.GetCurrentUserAsync();
        return Ok(response);
    }

    [HttpDelete("user/{id}")]
    [Authorize]
    public async Task<IActionResult> Delete(Guid id)
    {
        await _userService.DeleteAsync(id);
        return Ok();
    }
}
