#region Namespace References
using Sitecore.Pipelines.HttpRequest;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
#endregion

namespace AuthenticationHelper.Pipelines
{  
    public class B2CUserResolver : HttpRequestProcessor
    {
        #region Custom Methods
        public override void Process(HttpRequestArgs args)
        {
            if (Sitecore.Context.User.IsAuthenticated) { return; }
            
            var loginResultUrl = Settings.SignInCallbackUrl;
            if (loginResultUrl.ToLower().EndsWith(args.Url.FilePathWithQueryString.ToLower()))
            {
                //We need to get the token and other post data that B2C sent us
                var idToken = HttpContext.Current.Request.Form["id_token"];
                var idstate = HttpContext.Current.Request.Form["state"];

                if (string.IsNullOrEmpty(idToken)) { return; }
                //Validate the token
                var validToken = B2CHelper.ValidateToken(idToken);
                if (validToken == null)
                {
                    if (!String.IsNullOrWhiteSpace(idstate))
                    {
                        Sitecore.Web.WebUtil.Redirect(idstate, false);
                        args.AbortPipeline();
                    }
                    else
                    {
                        return;
                    }
                }
               
                Dictionary<string, string> tokenClaims = new Dictionary<string, string>();
                foreach (var c in validToken.Claims)
                {
                    tokenClaims.Add(c.Type, c.Value);
                }
                bool loggedin = this.CreateAndLoginUser(tokenClaims["given_name"], tokenClaims["given_name"] + " " + tokenClaims["family_name"], tokenClaims);
                if (loggedin)
                {
                    if (!String.IsNullOrWhiteSpace(idstate))
                    {
                        Sitecore.Web.WebUtil.Redirect(idstate, false);
                        args.AbortPipeline();
                    }
                }
            }
        }

        private bool CreateAndLoginUser(string userName, string fullName, Dictionary<string, string> props)
        {
            bool _res = false;
            Sitecore.Security.Accounts.User currentUser;
            bool success = B2CHelper.CreateVirtualUser(userName, fullName, props, out currentUser);
            if (success)
            {
                bool loggedin = Sitecore.Security.Authentication.AuthenticationManager.LoginVirtualUser(currentUser);
                _res = loggedin;
            }
            return _res;
        }
        #endregion
    }
}