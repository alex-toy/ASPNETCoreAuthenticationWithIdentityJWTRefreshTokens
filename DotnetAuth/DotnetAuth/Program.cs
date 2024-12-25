
using DotnetAuth.Config;
using DotnetAuth.Entities;
using DotnetAuth.Exceptions;
using DotnetAuth.Mappings;
using DotnetAuth.Repo;
using Microsoft.AspNetCore.Identity;

namespace DotnetAuth
{
    public class Program
    {
        public static void Main(string[] args)
        {
            WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

            builder.Services.AddHttpContextAccessor();
            builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

            builder.Services.AddProblemDetails();

            builder.Services.AddControllers();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.ConfigureSwagger();

            string connectionString = builder.Configuration.GetConnectionString("sqlConnection")!;
            builder.Services.ConfigureDatabase(connectionString);

            builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();


            builder.Services.ConfigureServices();


            // Regsitering AutoMapper
            builder.Services.AddAutoMapper(typeof(MappingProfile).Assembly);


            // Adding Jwt from extension method
            builder.Services.ConfigureIdentity();
            builder.Services.ConfigureJwt(builder.Configuration);
            builder.Services.ConfigureCors();





            var app = builder.Build();

            app.UseCors("CorsPolicy");

            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
