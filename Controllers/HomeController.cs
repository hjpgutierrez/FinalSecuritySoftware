using FinalSecuritySoftware.Areas.Identity.Data;
using FinalSecuritySoftware.Data;
using FinalSecuritySoftware.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using NuGet.Common;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Net.Http.Headers;
using System.Text;
using static System.Net.Mime.MediaTypeNames;

namespace FinalSecuritySoftware.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly UserManager<FinalSecuritySoftwareUser> _userManager;

        public HomeController(ILogger<HomeController> logger,
            UserManager<FinalSecuritySoftwareUser> userManager)
        {
            _logger = logger;
            _userManager = userManager;
        }

        [AllowAnonymous]
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult DownloadUserFile()
        {
            return View();
        }

        [Authorize]
        public FileResult Download()
        {
            var userList = _userManager.Users.ToList();

            using (MemoryStream stream = new MemoryStream())
            {
                TextWriter tw = new StreamWriter(stream);
                foreach (var user in userList)
                {
                    tw.WriteLine(string.Join("\t", user.NormalizedUserName, user.FirstName, user.LastName, user.PasswordHash));
                }
                tw.Flush();
                byte[] bytes = stream.ToArray();
                stream.Close();
                return File(bytes, "text/plain", "group1Users.txt");
            }        
        }




        [Authorize]
        public IActionResult EncryptFile()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
    
}