namespace DotnetAuth.Services;

public interface ICurrentUserService
{
    public string? GetUserId();
}
