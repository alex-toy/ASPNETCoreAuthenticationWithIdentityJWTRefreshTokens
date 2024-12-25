namespace DotnetAuth.Dtos;

public class ErrorResponseDto
{
    public string Titel { get; set; }
    public int StatusCode { get; set; }
    public string Message { get; set; }
}
