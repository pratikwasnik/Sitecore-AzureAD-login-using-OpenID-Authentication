#region Namespace References
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
#endregion

namespace sitecoread.Controllers
{
    public class SampleController : Controller
    {
        // GET: Sample
        #region Custom Methods
        public ActionResult Index()
        {
            return View();
        }

        public void CallSignInUp()
        {
            AuthenticationHelper.Controllers.B2CAuthorizationController obj = new AuthenticationHelper.Controllers.B2CAuthorizationController();
            obj.SignInUp();
        }

        public void CallSignOut()
        {
            AuthenticationHelper.Controllers.B2CAuthorizationController obj = new AuthenticationHelper.Controllers.B2CAuthorizationController();
            obj.SignOut();
        }
        #endregion
    }
}