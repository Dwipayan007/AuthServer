using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using Microsoft.Owin.Security.OAuth;
using System.Web.Http;
using System.Web.Cors;
using Microsoft.Owin.Cors;

[assembly: OwinStartup(typeof(AuthServer.Startup))]

namespace AuthServer
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureOAuth(app);
            //var Policy = new CorsPolicy {AllowAnyMethod=true,AllowAnyHeader=true,AllowAnyOrigin=true,SupportsCredentials=true };
           // Policy.ExposedHeaders.Add("X-roles");
            //app.UseCors(new CorsOptions { PolicyProvider = new CorsPolicyProvider { PolicyResolver = context => Task.FromResult(Policy) } });
            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
        }

        public void ConfigureOAuth(IAppBuilder app)
        {
            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(1),
                Provider = new SimpleAuthorizationServerProvider()
            };

            // Token Generation
            app.UseOAuthAuthorizationServer(OAuthServerOptions);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());

        }
    }
}
