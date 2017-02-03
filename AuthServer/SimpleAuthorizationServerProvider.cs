using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Security;
using MySql.Data;


namespace AuthServer
{
    public class SimpleAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            try
            {
                context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });
                context.OwinContext.Response.Headers.Add("Access-Control-Expose-Headers", new[] { "X-roles", "X-uid" });
                var formData = await context.Request.ReadFormAsync();
                var acc = formData["account"];
                int uid = authDbUtility.ValidateUser(context.UserName, context.Password, acc);
                if (uid == 0)
                {
                    context.SetError("invalid_grant", "The username or password is incorrect.");
                    return;
                }
                List<string> rol = authDbUtility.GetRolesForUser(uid);
                string roles = String.Join(",", rol.ToArray());

                var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, uid.ToString()));
                identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
                identity.AddClaim(new Claim(ClaimTypes.Role, roles));

                context.Validated(identity);
                context.Response.Headers.Add("X-roles", rol.ToArray());
                context.Response.Headers.Add("X-uid", new[] { uid.ToString() });
            }
            catch (Exception ee)
            {
                context.SetError("invalid_grant", "The username or password is incorrect.");
                return;
            }

        }
    }
}