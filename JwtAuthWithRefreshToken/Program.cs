using JwtAuthWithRefreshToken.Helpers;
using JwtAuthWithRefreshToken.Models;
using JwtAuthWithRefreshToken.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
ConfigurationManager configuration = builder.Configuration;
// Add services to the container.

builder.Services.AddControllers().AddJsonOptions(x => x.JsonSerializerOptions.IgnoreNullValues = true);
builder.Services.AddDbContext<DataContext>(x => x.UseInMemoryDatabase("TestDb"));
builder.Services.AddCors();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

//Configure strongly typed settings objects 
var appSettingsSection = configuration.GetSection("AppSettings");
builder.Services.Configure<AppSettings>(appSettingsSection);

//Configure JWT Auth 
var appSettings = appSettingsSection.Get<AppSettings>();    
var key = Encoding.ASCII.GetBytes(appSettings.Secret);
builder.Services.AddAuthentication(x =>
{
    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).
AddJwtBearer(x =>
{
    x.RequireHttpsMetadata = false;
    x.SaveToken = true;
    x.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey =new SymmetricSecurityKey(key),
        ValidateIssuer =false,
        ValidateAudience =false,
        ClockSkew  = TimeSpan.Zero
    };
});

builder.Services.AddScoped<IUserService, UserService>();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<DataContext>();
    // use context
    dbContext.Users.Add(new User {Firstname="test", Lastname="test", Id=1, Password="test", Username="test" });
    dbContext.SaveChanges();
}

app.UseHttpsRedirection();

app.UseAuthorization();
app.UseMiddleware<JwtMiddleware>();

app.MapControllers();

app.UseCors(x => x
             .SetIsOriginAllowed(origin => true)
             .AllowAnyOrigin()
             .AllowAnyHeader()
             .AllowAnyMethod()
             .AllowCredentials()
);

app.UseAuthentication();
app.UseAuthorization();

app.Run();
