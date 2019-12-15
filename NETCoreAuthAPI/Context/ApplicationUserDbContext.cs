using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using NETCoreAuthAPI.Models;
using NETCoreAuthAPI.Models.AccountModels;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace NETCoreAuthAPI.Context
{
    //public class DataContext : DbContext
    //{
    //    public DataContext(DbContextOptions<DataContext> options) : base(options) { }

    //    public DbSet<User> Users { get; set; }
    //}

    public class ApplicationUserDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationUserDbContext(DbContextOptions<ApplicationUserDbContext> options) : base(options)
        {


        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            // Invoke the Identity version of this method to configure relationships 
            // in the AspNetIdentity models/tables
            base.OnModelCreating(builder);


        
      
        }

        public DbSet<ApplicationUser> ApplicationUsers { get; set; }
    
        //object name must be same as table name defined in Migrations


        public virtual void Save()
        {
            base.SaveChanges();
        }
        public static string UserProvider
        {
            get
            {
                bool isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
                if (isWindows)
                {
                    if (!string.IsNullOrEmpty(WindowsIdentity.GetCurrent().Name))
                        return WindowsIdentity.GetCurrent().Name.Split('\\')[1];
                    else
                    {
                        return "TESTINGG User";
                    }
                }
                else
                {
                    return "TESTINGG User";
                }
                //return string.Empty;
            }
        }

        public Func<DateTime> TimestampProvider { get; set; } = ()
            => DateTime.UtcNow;
        public override int SaveChanges()
        {
            TrackChanges();
            return base.SaveChanges();
        }

        public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = new CancellationToken())
        {
            TrackChanges();
            return await base.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        private void TrackChanges()
        {
            DateTime currentDateTime = DateTime.UtcNow;

            foreach (var entry in this.ChangeTracker.Entries().Where(e => e.State == EntityState.Added || e.State == EntityState.Modified))
            {
                if (entry.Entity is IAuditable)
                {
                    var auditable = entry.Entity as IAuditable;
                    if (entry.State == EntityState.Added)
                    {
                        auditable.CreatedBy = UserProvider;//  
                        auditable.CreatedOn = currentDateTime;
                        auditable.UpdatedOn = currentDateTime;
                    }
                    else
                    {
                        auditable.UpdatedBy = UserProvider;
                        auditable.UpdatedOn = currentDateTime;
                    }
                }
            }
        }
    }
}