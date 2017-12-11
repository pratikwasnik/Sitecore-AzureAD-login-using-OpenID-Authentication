namespace AuthenticationHelper
{
    public static class Settings
    {
        #region Variables
        public static string DirectoryName = "yourDirectoryName"; //e.g."sitecoread" + ".onmicrosoft.com";

        public static string SignInCallbackUrl = ""; //e.g."https: //sitecoread/demo"

        public static string PublicKey = "true";

        public static string TempCookieName = "AD-User-Data";

        public static string Scope = "true";

        public static string ClientId = "Yourclienid";

        public static string ValidIssuer = "true";

        public static string AuthorizeEndpoint = "https://login.microsoftonline.com/YourEndpointURL";

        public static string LogoutEndpoint = "https://login.microsoftonline.com/YourEndpointURL";

        public static string PolicyName = "YourPolicyName";

        //State Management Application not Azure AD Application
        public static string ApplicationName = "_B2CMETADATA_";

        public static string SignOutRedirectUrl = "";//e.g. "https: //sitecoread/home"
        #endregion
    }
}
