using AutoMapper;
using DotnetAuth.Dtos;
using DotnetAuth.Entities;

namespace DotnetAuth.Mappings;

public class MappingProfile : Profile
{
    public MappingProfile()
    {
        CreateMap<ApplicationUser, UserResponse>();
        CreateMap<ApplicationUser, CurrentUserResponse>();
        CreateMap<RegistrationDto, ApplicationUser>();
    }
}
