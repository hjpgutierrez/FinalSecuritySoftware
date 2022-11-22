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
using System.IO.Pipes;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using static System.Net.Mime.MediaTypeNames;

namespace FinalSecuritySoftware.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly UserManager<FinalSecuritySoftwareUser> _userManager;
        private readonly IWebHostEnvironment _hostingEnvironment;


        public HomeController(ILogger<HomeController> logger,
            UserManager<FinalSecuritySoftwareUser> userManager,
            IWebHostEnvironment environment)
        {
            _logger = logger;
            _userManager = userManager;
            _hostingEnvironment = environment;
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

        [HttpPost]
        public ActionResult Encrypt(IFormFile file)
        {
            using (var reader = new StreamReader(file.OpenReadStream()))
            {
                var fileContent = reader.ReadToEnd();

                using (MemoryStream stream = new MemoryStream())
                {
                    TextWriter tw = new StreamWriter(stream);
                    using (Aes aes = Aes.Create())
                    {
                        byte[] key =
                                {
                                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16
                                };
                        aes.Key = key;
                        byte[] iv = aes.IV;
                        tw.Write(iv);

                        using (CryptoStream cryptoStream = new(
                            stream,
                            aes.CreateEncryptor(),
                            CryptoStreamMode.Write))
                        {
                            // By default, the StreamWriter uses UTF-8 encoding.
                            // To change the text encoding, pass the desired encoding as the second parameter.
                            // For example, new StreamWriter(cryptoStream, Encoding.Unicode).
                            using (StreamWriter encryptWriter = new(cryptoStream))
                            {
                                encryptWriter.WriteLine(fileContent);
                            }
                        }
                    }
                    
                    byte[] bytes = stream.ToArray();
                    stream.Close();
                    return File(bytes, "text/plain", "ENCRYPTED.txt");
                }
            }
        }

        [HttpPost]
        public async Task<ActionResult> Decrypt(IFormFile file)
        {
            string filePath = string.Empty;
            string decryptedMessage = string.Empty;
            string fileName = string.Empty;

            try
            {              

                string uploadsFolder = Path.Combine(_hostingEnvironment.WebRootPath, "uploads");

                if (!System.IO.Directory.Exists(uploadsFolder))
                {
                    System.IO.Directory.CreateDirectory(uploadsFolder);
                }

                if (file.Length > 0)
                {
                    fileName = string.Concat(DateTime.Now.Millisecond, file.FileName);
                    filePath = Path.Combine(uploadsFolder, fileName);
                    using (Stream fileStream = new FileStream(filePath, FileMode.OpenOrCreate))
                    {
                        await file.CopyToAsync(fileStream);
                    }
                }

                using (FileStream fileStream = new(filePath, FileMode.Open))
                {
                    using (Aes aes = Aes.Create())
                    {
                        byte[] iv = new byte[aes.IV.Length];
                        int numBytesToRead = aes.IV.Length;
                        int numBytesRead = 0;
                        while (numBytesToRead > 0)
                        {
                            int n = fileStream.Read(iv, numBytesRead, numBytesToRead);
                            if (n == 0) break;

                            numBytesRead += n;
                            numBytesToRead -= n;
                        }

                        byte[] key =
                        {
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16
                    };

                        using (CryptoStream cryptoStream = new(
                           fileStream,
                           aes.CreateDecryptor(key, iv),
                           CryptoStreamMode.Read))
                        {
                            // By default, the StreamReader uses UTF-8 encoding.
                            // To change the text encoding, pass the desired encoding as the second parameter.
                            // For example, new StreamReader(cryptoStream, Encoding.Unicode).
                            using (StreamReader decryptReader = new(cryptoStream))
                            {
                                decryptedMessage = await decryptReader.ReadToEndAsync();

                                using (MemoryStream stream = new MemoryStream())
                                {
                                    TextWriter tw = new StreamWriter(stream);
                                    tw.Write(decryptedMessage);
                                    tw.Flush();
                                    byte[] bytes = stream.ToArray();
                                    stream.Close();
                                    return File(bytes, "text/plain", fileName);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception: {ex.Message}");
            }


            return null;

        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
    
}