using FinalSecuritySoftware.Areas.Identity.Data;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace FinalSecuritySoftware.Data
{
    public class ApplicationDbContext : IdentityDbContext<FinalSecuritySoftwareUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }
    }
}