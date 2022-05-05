using JwtAuthWithRefreshToken.Models;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthWithRefreshToken.Helpers
{
    public class DataContext : DbContext
    {
        public DbSet<User> Users { get; set; }
        public DataContext(DbContextOptions<DataContext> options) : base(options) { }
    }
}
