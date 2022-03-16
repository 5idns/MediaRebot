using System.IdentityModel.Tokens.Jwt;
using MediaRebot;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

// Add services to the container.
builder.Services.AddControllersWithViews();

SSOConfiguration ssoConfiguration = new SSOConfiguration();
builder.Configuration.GetSection(nameof(SSOConfiguration)).Bind(ssoConfiguration);

var authenticationBuilder = builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = "oidc";

    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultForbidScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignOutScheme = CookieAuthenticationDefaults.AuthenticationScheme;
}).AddCookie(
    CookieAuthenticationDefaults.AuthenticationScheme,
    options =>
    {
        options.Cookie.Name = ssoConfiguration.IdentityCookieName;
    })
.AddOpenIdConnect(
    "oidc", 
    options =>
    {
        options.Authority = ssoConfiguration.IdentityServerBaseUrl;
        options.RequireHttpsMetadata = ssoConfiguration.RequireHttpsMetadata;
        options.ClientId = ssoConfiguration.ClientId;
        options.ClientSecret = ssoConfiguration.ClientSecret;
        options.ResponseType = ssoConfiguration.OidcResponseType;

        options.Scope.Clear();
        foreach (var scope in ssoConfiguration.Scopes)
        {
            options.Scope.Add(scope);
        }

        options.ClaimActions.MapJsonKey(
            ssoConfiguration.TokenValidationClaimRole,
            ssoConfiguration.TokenValidationClaimRole,
            ssoConfiguration.TokenValidationClaimRole
            );

        options.SaveTokens = true;

        options.GetClaimsFromUserInfoEndpoint = true;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            NameClaimType = ssoConfiguration.TokenValidationClaimName,
            RoleClaimType = ssoConfiguration.TokenValidationClaimRole
        };

        options.Events = new OpenIdConnectEvents
        {
            OnMessageReceived = context => OnMessageReceived(context, ssoConfiguration),
            OnRedirectToIdentityProvider = context => OnRedirectToIdentityProvider(context, ssoConfiguration)
        };
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
}
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();
app.UseAuthentication();


app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

static Task OnMessageReceived(MessageReceivedContext context, SSOConfiguration ssoConfiguration)
{
    if (context.Properties != null)
    {
        context.Properties.IsPersistent = true;
        context.Properties.ExpiresUtc = new DateTimeOffset(DateTime.Now.AddHours(ssoConfiguration.IdentityCookieExpiresUtcHours));
    }
    return Task.FromResult(0);
}

static Task OnRedirectToIdentityProvider(RedirectContext n, SSOConfiguration ssoConfiguration)
{
    n.ProtocolMessage.RedirectUri = ssoConfiguration.IdentityRedirectUri;

    return Task.FromResult(0);
}