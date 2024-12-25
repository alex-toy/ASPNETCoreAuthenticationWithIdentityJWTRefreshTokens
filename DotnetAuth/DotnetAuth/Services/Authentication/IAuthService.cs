using DotnetAuth.Dtos;

namespace DotnetAuth.Services.Authentication;

public interface IAuthService
{
    //Task<CurrentUserResponse> GetCurrentUserAsync();
    Task<UserDto> GetByIdAsync(Guid id);
    Task<UserDto> UpdateAsync(Guid id, UpdateUserDto request);
    Task DeleteAsync(Guid id);
    //Task<RevokeRefreshTokenResponse> RevokeRefreshToken(RefreshTokenRequest refreshTokenRemoveRequest);
    //Task<CurrentUserResponse> RefreshTokenAsync(RefreshTokenRequest request);
    //Task<UserResponse> LoginAsync(UserLoginRequest request);
}
