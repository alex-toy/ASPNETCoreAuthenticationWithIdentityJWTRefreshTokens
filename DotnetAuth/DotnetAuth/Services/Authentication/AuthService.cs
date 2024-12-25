using AutoMapper;
using DotnetAuth.Dtos;
using DotnetAuth.Entities;
using DotnetAuth.Services.Tokens;
using DotnetAuth.Services.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace DotnetAuth.Services.Authentication;

public class AuthService : IAuthService
{
    private readonly ITokenService _tokenService;
    private readonly IUserService _userService;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IMapper _mapper;
    private readonly ILogger<AuthService> _logger;

    public AuthService(ITokenService tokenService, IUserService currentUserService, UserManager<ApplicationUser> userManager, IMapper mapper, ILogger<AuthService> logger)
    {
        _tokenService = tokenService;
        _userService = currentUserService;
        _userManager = userManager;
        _mapper = mapper;
        _logger = logger;
    }

    public async Task<UserDto> RegisterAsync(RegistrationDto request)
    {
        _logger.LogInformation("Registering user");
        ApplicationUser? existingUser = await _userManager.FindByEmailAsync(request.Email);
        if (existingUser is not null)
        {
            _logger.LogError("Email already exists");
            throw new Exception("Email already exists");
        }

        ApplicationUser newUser = _mapper.Map<ApplicationUser>(request);

        newUser.UserName = GenerateUserName(request.FirstName, request.LastName);
        IdentityResult result = await _userManager.CreateAsync(newUser, request.Password);
        if (!result.Succeeded)
        {
            string errors = string.Join(", ", result.Errors.Select(e => e.Description));
            _logger.LogError("Failed to create user: {errors}", errors);
            throw new Exception($"Failed to create user: {errors}");
        }
        _logger.LogInformation("User created successfully");
        await _tokenService.GenerateToken(newUser);
        newUser.CreateAt = DateTime.Now;
        newUser.UpdateAt = DateTime.Now;
        return _mapper.Map<UserDto>(newUser);
    }

    public async Task<UserDto> LoginAsync(LoginDto request)
    {
        if (request is null)
        {
            _logger.LogError("Login request is null");
            throw new ArgumentNullException(nameof(request));
        }

        ApplicationUser? user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null || !await _userManager.CheckPasswordAsync(user, request.Password))
        {
            _logger.LogError("Invalid email or password");
            throw new Exception("Invalid email or password");
        }

        string token = await _tokenService.GenerateToken(user);

        string refreshToken = _tokenService.GenerateRefreshToken();

        using var sha256 = SHA256.Create();
        byte[] refreshTokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(refreshToken));
        user.RefreshToken = Convert.ToBase64String(refreshTokenHash);
        user.RefreshTokenExpiryTime = DateTime.Now.AddDays(2);

        user.CreateAt = DateTime.Now;

        IdentityResult result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            string errors = string.Join(", ", result.Errors.Select(e => e.Description));
            _logger.LogError("Failed to update user: {errors}", errors);
            throw new Exception($"Failed to update user: {errors}");
        }

        UserDto userResponse = _mapper.Map<ApplicationUser, UserDto>(user);
        userResponse.AccessToken = token;
        userResponse.RefreshToken = refreshToken;

        return userResponse;
    }

    public async Task<UserDto> RefreshTokenAsync(RefreshTokenDto request)
    {
        _logger.LogInformation("RefreshToken");

        using var sha256 = SHA256.Create();
        var refreshTokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(request.RefreshToken));
        string hashedRefreshToken = Convert.ToBase64String(refreshTokenHash);

        ApplicationUser? user = await _userManager.Users.FirstOrDefaultAsync(u => u.RefreshToken == hashedRefreshToken);
        if (user is null)
        {
            _logger.LogError("Invalid refresh token");
            throw new Exception("Invalid refresh token");
        }

        if (user.RefreshTokenExpiryTime < DateTime.Now)
        {
            _logger.LogWarning("Refresh token expired for user ID: {UserId}", user.Id);
            throw new Exception("Refresh token expired");
        }

        string newAccessToken = await _tokenService.GenerateToken(user);
        _logger.LogInformation("Access token generated successfully");
        UserDto currentUserResponse = _mapper.Map<UserDto>(user);
        currentUserResponse.AccessToken = newAccessToken;
        return currentUserResponse;
    }

    public async Task<RevokeRefreshTokenDto> RevokeRefreshToken(RefreshTokenDto refreshTokenRemoveRequest)
    {
        _logger.LogInformation("Revoking refresh token");

        try
        {
            using var sha256 = SHA256.Create();
            byte[] refreshTokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(refreshTokenRemoveRequest.RefreshToken));
            string hashedRefreshToken = Convert.ToBase64String(refreshTokenHash);

            ApplicationUser? user = await _userManager.Users.FirstOrDefaultAsync(u => u.RefreshToken == hashedRefreshToken);
            if (user is null)
            {
                _logger.LogError("Invalid refresh token");
                throw new Exception("Invalid refresh token");
            }

            if (user.RefreshTokenExpiryTime < DateTime.Now)
            {
                _logger.LogWarning("Refresh token expired for user ID: {UserId}", user.Id);
                throw new Exception("Refresh token expired");
            }

            user.RefreshToken = null;
            user.RefreshTokenExpiryTime = null;

            IdentityResult result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                _logger.LogError("Failed to update user");
                return new RevokeRefreshTokenDto
                {
                    Message = "Failed to revoke refresh token"
                };
            }
            _logger.LogInformation("Refresh token revoked successfully");
            return new RevokeRefreshTokenDto
            {
                Message = "Refresh token revoked successfully"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError("Failed to revoke refresh token: {ex}", ex.Message);
            throw new Exception("Failed to revoke refresh token");
        }
    }

    private string GenerateUserName(string firstName, string lastName)
    {
        string baseUsername = $"{firstName}{lastName}".ToLower();

        string username = baseUsername;
        int count = 1;
        while (_userManager.Users.Any(u => u.UserName == username))
        {
            username = $"{baseUsername}{count}";
            count++;
        }
        return username;
    }
}
