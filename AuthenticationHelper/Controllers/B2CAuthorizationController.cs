#region Namespace References
using Sitecore.Web;
using System.Web.Mvc;
#endregion

namespace AuthenticationHelper.Controllers
{
    public class B2CAuthorizationController : Controller
    {
        #region Custom Methods
        [System.Web.Mvc.HttpGet]
        [AllowAnonymous]
        public void SignInUp()
        {                        
            if (!Sitecore.Context.User.IsAuthenticated)
            {                
                B2CHelper.InitiateCustomerSignInUp((B2CMetadata)System.Web.HttpContext.Current.Application[Settings.ApplicationName]);
            }
        }

        public void SignOut()
        {
            B2CHelper.LogOut();                        
            WebUtil.Redirect(Settings.SignOutRedirectUrl);                        
        }
        #endregion
    }
}