using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Jwt.Models
{

    // this class for response login or registration 
    public class AuthModel
    {
        public string Message { get; set; }
        public bool IsAuth { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public string Token { get; set; }
        public List<string> Roles { get; set; }
        public DateTime ExpiresOn { get; set; }
    }
}
