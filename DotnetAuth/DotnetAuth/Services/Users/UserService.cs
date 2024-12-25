using AutoMapper;
using DotnetAuth.Dtos;
using DotnetAuth.Entities;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace DotnetAuth.Services.Users;

public class UserService : IUserService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IMapper _mapper;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<UserService> _logger;

    public UserService(UserManager<ApplicationUser> userManager, IMapper mapper, ILogger<UserService> logger, IHttpContextAccessor httpContextAccessor)
    {
        _userManager = userManager;
        _mapper = mapper;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<UserDto> GetCurrentUserAsync()
    {
        string? userId = _httpContextAccessor.HttpContext?.User?.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId is null)
        {
            _logger.LogError("User not found");
            throw new Exception("User not found");
        }
        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            _logger.LogError("User not found");
            throw new Exception("User not found");
        }
        return _mapper.Map<UserDto>(user);
    }

    public async Task<UserDto> GetByIdAsync(Guid id)
    {
        _logger.LogInformation("Getting user by id");
        ApplicationUser? user = await _userManager.FindByIdAsync(id.ToString());
        if (user is null)
        {
            _logger.LogError("User not found");
            throw new Exception("User not found");
        }
        _logger.LogInformation("User found");
        return _mapper.Map<UserDto>(user);
    }

    public async Task<UserDto> UpdateAsync(Guid id, UpdateUserDto request)
    {
        ApplicationUser? user = await _userManager.FindByIdAsync(id.ToString());
        if (user is null)
        {
            _logger.LogError("User not found");
            throw new Exception("User not found");
        }

        user.UpdateAt = DateTime.Now;
        user.FirstName = request.FirstName;
        user.LastName = request.LastName;
        user.Email = request.Email;
        user.Gender = request.Gender;

        await _userManager.UpdateAsync(user);
        return _mapper.Map<UserDto>(user);
    }

    public async Task DeleteAsync(Guid id)
    {
        ApplicationUser? user = await _userManager.FindByIdAsync(id.ToString());
        if (user is null)
        {
            _logger.LogError("User not found");
            throw new Exception("User not found");
        }
        await _userManager.DeleteAsync(user);
    }
}
