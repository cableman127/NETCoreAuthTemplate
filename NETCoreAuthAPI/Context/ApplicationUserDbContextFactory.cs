using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using System.IO;

namespace NETCoreAuthAPI.Context
{
    public class ApplicationUserDbContextFactory : IDesignTimeDbContextFactory<ApplicationUserDbContext>
    {
        public ApplicationUserDbContext CreateDbContext(string[] args)
        {
            var dbContext = new ApplicationUserDbContext(new DbContextOptionsBuilder<ApplicationUserDbContext>().UseNpgsql(
               new ConfigurationBuilder()
                   .AddJsonFile(Path.Combine(Directory.GetCurrentDirectory(), $"appsettings.Development.json"))
                   .Build()
                   .GetConnectionString("DefaultConnection")
               ).Options);

            //dbContext.Database.Migrate();
            return dbContext;
        }
    }
}
