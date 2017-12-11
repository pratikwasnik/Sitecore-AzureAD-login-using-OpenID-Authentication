#region Namespace References
using Sitecore.Web;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Script.Serialization;
using System.Security.Cryptography;
using System.IdentityModel.Tokens;
using System.IdentityModel.Selectors;
using System.Text;
#endregion



namespace AuthenticationHelper
{

    public static class B2CHelper
    {
        #region Variables        
        static string appID = Settings.ClientId;
        static string redirectURL = Settings.SignInCallbackUrl;
        static string policyName = Settings.PolicyName;
        static string directoryName = Settings.DirectoryName;
        #endregion

        #region Custom Methods
        public static void InitializeMetadata()
        {
            if (HttpContext.Current.Application[Settings.ApplicationName] != null) return;
            string metadataEndpoint = String.Format("https://login.microsoftonline.com/{0}/v2.0/.well-known/openid-configuration?p={1}", directoryName, policyName);

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(metadataEndpoint);
            request.Method = "GET";
            string respJson = String.Empty;
            using (var response = request.GetResponse())
            {
                using (var sr = new StreamReader(response.GetResponseStream()))
                {
                    respJson = sr.ReadToEnd();
                }
            }
            var serializer = new JavaScriptSerializer();

            B2CMetadata config = serializer.Deserialize<B2CMetadata>(respJson);

            config = serializer.Deserialize<B2CMetadata>(respJson);
            HttpContext.Current.Application[Settings.ApplicationName] = config;
        }

        public static KeysWrapper GetB2CKeys()
        {
            var config = (B2CMetadata)HttpContext.Current.Application[Settings.ApplicationName];
            HttpWebRequest keysRequest = (HttpWebRequest)WebRequest.Create(config.jwks_uri);
            keysRequest.Method = "GET";
            string keysJson = String.Empty;
            using (var kresponse = keysRequest.GetResponse())
            {
                using (var ksr = new StreamReader(kresponse.GetResponseStream()))
                {
                    keysJson = ksr.ReadToEnd();
                }
            }
            var keySerializer = new JavaScriptSerializer();
            KeysWrapper keys = keySerializer.Deserialize<KeysWrapper>(keysJson);

            return keys;
        }

        public static void InitiateCustomerSignInUp(B2CMetadata b2cMetadata)
        {
            var config = (B2CMetadata)HttpContext.Current.Application[Settings.ApplicationName];
            config = config != null ? config : b2cMetadata;
            string authEndpoint = config.authorization_endpoint;
            //We are using the Nonce parameter to avoid replay attacks
            string nonce = Guid.NewGuid().ToString();
            HttpContext.Current.Session["_NONCE_"] = nonce;

            string state = redirectURL;
            string rType = "id_token";
            string rMode = "form_post";
            string clientId = appID;
            string redirUri = redirectURL;
            string scope = "openid";
            string policy = policyName;
            string prompt = "login";

            var sb = new StringBuilder(authEndpoint)
    .Append($"&client_id={clientId}")
    .Append($"&scope={scope}")
    .Append($"&response_type={rType}&response_mode={rMode}")
    .Append($"&redirect_uri={redirUri}")
    .Append($"&state={state}&nonce={nonce}")
    .Append($"&prompt={prompt}");
            WebUtil.Redirect(sb.ToString());
        }

        public static void LogOut()
        {
            //Just logout
            Sitecore.Security.Authentication.AuthenticationManager.Logout();
        }

        public static bool CreateVirtualUser(string userName, string displayName, Dictionary<string, string> properties, out Sitecore.Security.Accounts.User user)
        {
            bool _res = false;
            user = null;
            try
            {
                string fullUsername = String.Format("extranet\\{0}", userName);
                // Create virtual user
                var virtualUser = Sitecore.Security.Authentication.AuthenticationManager.BuildVirtualUser(fullUsername, true);
                virtualUser.RuntimeSettings.Load();
                virtualUser.RuntimeSettings.AddedRoles.Clear();

                //set profile properties
                virtualUser.Profile.Email = userName;
                virtualUser.Profile.Name = displayName;
                foreach (var prop in properties)
                {
                    virtualUser.Profile.SetCustomProperty(prop.Key, prop.Value);
                }
                virtualUser.Profile.Save();
                virtualUser.RuntimeSettings.IsVirtual = true;

                virtualUser.RuntimeSettings.Save();
                user = virtualUser;
                _res = true;
            }
            catch (Exception ex)
            {
                _res = false;
            }
            return _res;
        }

        public static JwtPayload ValidateToken(string rawToken)
        {
            JwtPayload token;
            if (Validate(rawToken, out token))
            {
                return token;
            }
            else
            {
                return null;
            }
        }
        private static bool Validate(string rawToken, out JwtPayload token)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                if (!handler.CanReadToken(rawToken) || !handler.CanValidateToken)
                {
                    token = null;
                    return false;
                }
                var tkn = handler.ReadToken(rawToken) as JwtSecurityToken;
                JwtHeader header = tkn.Header;
                JwtPayload jwtPayload = tkn.Payload;
                //Get the keys for validation
                var keysDictionary = B2CHelper.GetB2CKeys();
                var key = keysDictionary.FindByKidValue(tkn.Header["kid"].ToString());
                var publicKey = new { e = key["e"], n = key["n"] };
                var signatureToValidate = tkn.EncodedHeader + "." + tkn.EncodedPayload;

                //Create a CryptoServiceProvider to represent the public key
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(
                new RSAParameters()
                {
                    Modulus = new Microsoft.Owin.Security.DataHandler.Encoder.Base64UrlTextEncoder().Decode(publicKey.n),
                    Exponent = new Microsoft.Owin.Security.DataHandler.Encoder.Base64UrlTextEncoder().Decode(publicKey.e),

                });
                var rawSignature = tkn.RawSignature;

                //Add the provider to the tokenvalidation parameters
                var options = new TokenValidationParameters()
                {
                    IssuerSigningKeyResolver =
                ((tk, st, kid, tvp) => { return new RsaSecurityKey(rsa); }),
                    ValidIssuer = tkn.Issuer,
                    ValidAudiences = tkn.Audiences,
                    ValidateLifetime = true,
                    ValidateIssuer = true,
                    CertificateValidator = X509CertificateValidator.None
                };
                SecurityToken secToken;

                //Call the validator with our keys
                handler.ValidateToken(rawToken, options, out secToken);
                token = jwtPayload;
                return true;
            }
            catch (SecurityTokenValidationException vex)
            {
                //Validation exceptions are caught here
                token = null;
                return false;
            }
            catch (Exception ex)
            {
                token = null;
                return false;
            }
        }
        #endregion
    }
}