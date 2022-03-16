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

var ssoConfiguration = new SSOConfiguration();
builder.Configuration.GetSection(nameof(SSOConfiguration)).Bind(ssoConfiguration);

builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
    options.Secure = CookieSecurePolicy.SameAsRequest;
    options.OnAppendCookie = cookieContext =>
        CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
    options.OnDeleteCookie = cookieContext =>
        CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
});

var authenticationBuilder = builder.Services.AddAuthentication(
    options =>
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

app.UseCookiePolicy();

app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.UseEndpoints(endpoints =>
{
    endpoints
        .MapDefaultControllerRoute()
        .RequireAuthorization();
});

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

static Task OnRedirectToIdentityProvider(RedirectContext context, SSOConfiguration ssoConfiguration)
{
    context.ProtocolMessage.RedirectUri = ssoConfiguration.IdentityRedirectUri;

    return Task.FromResult(0);
}

static void CheckSameSite(HttpContext httpContext, CookieOptions options)
{
    if (options.SameSite == SameSiteMode.None)
    {
        var userAgent = httpContext.Request.Headers["User-Agent"].ToString();
        if (!httpContext.Request.IsHttps || DisallowsSameSiteNone(userAgent))
        {
            // For .NET Core < 3.1 set SameSite = (SameSiteMode)(-1)
            options.SameSite = SameSiteMode.Unspecified;
        }
    }
}

static bool DisallowsSameSiteNone(string userAgent)
{
    // Cover all iOS based browsers here. This includes:
    // - Safari on iOS 12 for iPhone, iPod Touch, iPad
    // - WkWebview on iOS 12 for iPhone, iPod Touch, iPad
    // - Chrome on iOS 12 for iPhone, iPod Touch, iPad
    // All of which are broken by SameSite=None, because they use the iOS networking stack
    if (userAgent.Contains("CPU iPhone OS 12") || userAgent.Contains("iPad; CPU OS 12"))
    {
        return true;
    }

    // Cover Mac OS X based browsers that use the Mac OS networking stack. This includes:
    // - Safari on Mac OS X.
    // This does not include:
    // - Chrome on Mac OS X
    // Because they do not use the Mac OS networking stack.
    if (userAgent.Contains("Macintosh; Intel Mac OS X 10_14") &&
        userAgent.Contains("Version/") && userAgent.Contains("Safari"))
    {
        return true;
    }

    // Cover Chrome 50-69, because some versions are broken by SameSite=None, 
    // and none in this range require it.
    // Note: this covers some pre-Chromium Edge versions, 
    // but pre-Chromium Edge does not require SameSite=None.
    if (userAgent.Contains("Chrome/5") || userAgent.Contains("Chrome/6"))
    {
        return true;
    }

    return false;
}