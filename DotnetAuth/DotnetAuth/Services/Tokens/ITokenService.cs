using DotnetAuth.Entities;

namespace DotnetAuth.Services.Tokens;

public interface ITokenService
{
    Task<string> GenerateToken(ApplicationUser user);
    string GenerateRefreshToken();
}
