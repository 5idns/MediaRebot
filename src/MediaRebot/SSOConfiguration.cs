namespace MediaRebot
{
    public class SSOConfiguration
    {
        public string IdentityRedirectUri { get; set; }
        public string[] Scopes { get; set; }
        public bool RequireHttpsMetadata { get; set; }
        public string IdentityCookieName { get; set; }
        public double IdentityCookieExpiresUtcHours { get; set; }
        public string TokenValidationClaimName { get; set; }
        public string TokenValidationClaimRole { get; set; }
        public string IdentityServerBaseUrl { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string OidcResponseType { get; set; }
    }
}
