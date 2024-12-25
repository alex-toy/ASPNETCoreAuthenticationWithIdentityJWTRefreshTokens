using DotnetAuth.Dtos;

namespace DotnetAuth.Services.Users;

public interface IUserService
{
    Task<UserDto> GetByIdAsync(Guid id);
    Task<UserDto> UpdateAsync(Guid id, UpdateUserDto request);
    Task DeleteAsync(Guid id);
    Task<UserDto> GetCurrentUserAsync();
}
