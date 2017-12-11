#region Namespace References
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
#endregion

namespace AuthenticationHelper
{
    [Serializable]
    public class B2CMetadata
    {
        #region Properties
        public string issuer { get; set; }
        public string authorization_endpoint { get; set; }
        public string token_endpoint { get; set; }
        public string end_session_endpoint { get; set; }
        public string jwks_uri { get; set; }
        public List<string> response_modes_supported { get; set; }
        public List<string> response_types_supported { get; set; }
        public List<string> scopes_supported { get; set; }
        public List<string> subject_types_supported { get; set; }
        public List<string> id_token_signing_alg_values_supported { get; set; }
        public List<string> token_endpoint_auth_methods_supported { get; set; }
        public List<string> claims_supported { get; set; }
        #endregion

        #region Constructor
        public B2CMetadata()
        {
        }
        #endregion
    }

    [Serializable]
    public class KeysWrapper
    {
        public List<Dictionary<string, string>> keys { get; set; }
        public KeysWrapper()
        {
            //Again, empty constructor to please the serializer
        }

        public Dictionary<string, string> FindByKidValue(string kid)
        {
            return keys.Where(k => k.Keys.Contains("kid") && k["kid"].Equals(kid)).FirstOrDefault();
        }
    }
}