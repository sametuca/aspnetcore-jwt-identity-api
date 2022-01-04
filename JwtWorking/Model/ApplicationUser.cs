using Microsoft.AspNetCore.Identity;

namespace JwtWorking.Model
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}
