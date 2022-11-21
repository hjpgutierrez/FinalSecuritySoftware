using Microsoft.AspNetCore.Identity;

namespace FinalSecuritySoftware.Areas.Identity.Data
{
    public class FinalSecuritySoftwareUser : IdentityUser
    {
        [PersonalData]
        public string FirstName { get; set; }

        [PersonalData]
        public string LastName { get; set; }
    }
}


