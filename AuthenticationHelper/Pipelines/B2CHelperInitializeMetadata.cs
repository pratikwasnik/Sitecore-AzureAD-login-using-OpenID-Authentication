#region Namespace References
using Sitecore.Pipelines.PreprocessRequest;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
#endregion

namespace AuthenticationHelper.Pipelines
{
    public class B2CHelperInitializeMetadata : PreprocessRequestProcessor
    {
        #region Custom Methods
        public override void Process(PreprocessRequestArgs args)
        {
            B2CHelper.InitializeMetadata();
        }
        #endregion
    }
}