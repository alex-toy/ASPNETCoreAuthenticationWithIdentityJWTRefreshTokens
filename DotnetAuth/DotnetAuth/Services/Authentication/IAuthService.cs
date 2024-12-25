using DotnetAuth.Dtos;

namespace DotnetAuth.Services.Authentication;

public interface IAuthService
{
    Task<RevokeRefreshTokenDto> RevokeRefreshToken(RefreshTokenDto refreshTokenRemoveRequest);
    Task<UserDto> RefreshTokenAsync(RefreshTokenDto request);
    Task<UserDto> LoginAsync(LoginDto request);
    Task<UserDto> RegisterAsync(RegistrationDto request);
}
