using Jwt.Helpers;
using Jwt.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Jwt.Services
{
    public class AuthService : IAuthService
    {

        private readonly UserManager<ApplicationUser> _UserManger;
        private readonly RoleManager<IdentityRole> _RoleMangeer;
        private readonly JwtModel _jwt;
        public AuthService(UserManager<ApplicationUser> user, IOptions<JwtModel> jwt, RoleManager<IdentityRole> roleManager)
        {
            _UserManger = user;
            _jwt = jwt.Value;
            _RoleMangeer = roleManager;
        }

        #region Register
        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            if (await _UserManger.FindByEmailAsync(model.Email) is not null)
                return new AuthModel { Message = "Email is already Registered" };

            if (await _UserManger.FindByNameAsync(model.Username) is not null)
                return new AuthModel { Message = "Name is already Registered" };

            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
            };
            var result = await _UserManger.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                var errors = string.Empty;
                foreach (var error in result.Errors)
                {
                    errors += $"{ error.Description}";
                }
                return new AuthModel { Message = errors };
            }
            await _UserManger.AddToRoleAsync(user, "User");

            var jwtSecurityToken = await CreateJwtToken(user);

            return new AuthModel
            {
                Message = "User registered successfully",
                Email = user.Email,
                ExpiresOn = jwtSecurityToken.ValidTo,
                IsAuth = true,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                UserName = user.UserName
            };
        }

        #endregion


        #region Login
        public async Task<AuthModel> LoginAsync(LoginModel model)
        {
            var authModel = new AuthModel();

            var user = await _UserManger.FindByEmailAsync(model.Email);

            if (user is null || !await _UserManger.CheckPasswordAsync(user, model.Password))
            {
                authModel.Message = "Email or Password is incorrect!";
                return authModel;
            }

            var jwtSecurityToken = await CreateJwtToken(user);
            var rolesList = await _UserManger.GetRolesAsync(user);

            authModel.Message = "User login successfully";
            authModel.IsAuth = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            authModel.Email = user.Email;
            authModel.UserName = user.UserName;
            authModel.ExpiresOn = jwtSecurityToken.ValidTo;
            authModel.Roles = rolesList.ToList();

            return authModel;
        }
        #endregion


        #region AddRole
        public async Task<string> AddRoleAsync(RoleModel model)
        {

            // get user 
            var user = await _UserManger.FindByIdAsync(model.UserId);


            //check role is exisit in table ,user too !
            if (user is null || !await _RoleMangeer.RoleExistsAsync(model.Role))
                return "Invalid user ID or Role";


            //check user take this role or no !
            if (await _UserManger.IsInRoleAsync(user, model.Role))
                return "User already assigned to this role";

            var result = await _UserManger.AddToRoleAsync(user, model.Role);

            return result.Succeeded ? string.Empty : "Sonething went wrong";
        }
        #endregion


        #region CreatTokenJwt
        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await _UserManger.GetClaimsAsync(user);
            var roles = await _UserManger.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }

        #endregion
    }
}
