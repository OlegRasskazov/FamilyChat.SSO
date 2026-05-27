using System.Security.Claims;
using System.Collections.Immutable;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace FamilyChat.SSO.Controllers
{
    public class AuthorizationController : Controller
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IOpenIddictScopeManager _scopeManager;

        public AuthorizationController(
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager,
            IOpenIddictScopeManager scopeManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _scopeManager = scopeManager;
        }

        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest()
                ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            if (!User.Identity?.IsAuthenticated ?? true)
            {
                var returnUrl = Request.PathBase + Request.Path + QueryString.Create(
                    Request.HasFormContentType
                        ? Request.Form.Select(parameter => new KeyValuePair<string, string?>(parameter.Key, parameter.Value))
                        : Request.Query.Select(parameter => new KeyValuePair<string, string?>(parameter.Key, parameter.Value)));

                return Challenge(new AuthenticationProperties
                {
                    RedirectUri = returnUrl
                }, IdentityConstants.ApplicationScheme);
            }

            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user profile cannot be loaded."
                    }));
            }

            var principal = await _signInManager.CreateUserPrincipalAsync(user);
            var identity = (ClaimsIdentity)principal.Identity!;
            identity.SetClaim(OpenIddictConstants.Claims.Subject, user.Id);
            principal.SetScopes(request.GetScopes());
            principal.SetResources(await GetResourcesAsync(principal.GetScopes()));

            foreach (var claim in principal.Claims)
            {
                claim.SetDestinations(GetDestinations(claim));
            }

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpGet("~/connect/logout")]
        [HttpPost("~/connect/logout")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Logout()
        {
            var request = HttpContext.GetOpenIddictServerRequest();

            await _signInManager.SignOutAsync();

            return SignOut(new AuthenticationProperties
            {
                RedirectUri = request?.PostLogoutRedirectUri ?? "/"
            }, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
        [HttpGet("~/connect/userinfo")]
        [HttpPost("~/connect/userinfo")]
        public async Task<IActionResult> UserInfo()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return Challenge(
                    authenticationSchemes: OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictValidationAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                        [OpenIddictValidationAspNetCoreConstants.Properties.ErrorDescription] = "The access token is no longer valid."
                    }));
            }

            var claims = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                [Claims.Subject] = await _userManager.GetUserIdAsync(user)
            };

            if (User.HasScope(Scopes.Email))
            {
                claims[Claims.Email] = await _userManager.GetEmailAsync(user);
                claims[Claims.EmailVerified] = await _userManager.IsEmailConfirmedAsync(user);
            }

            if (User.HasScope(Scopes.Profile))
            {
                claims[Claims.Name] = await _userManager.GetUserNameAsync(user);
            }

            if (User.HasScope(Scopes.Roles))
            {
                claims[Claims.Role] = await _userManager.GetRolesAsync(user);
            }

            return Ok(claims);
        }

        private async Task<IEnumerable<string>> GetResourcesAsync(IEnumerable<string> scopes)
        {
            var resources = new List<string>();

            await foreach (var resource in _scopeManager.ListResourcesAsync(scopes.ToImmutableArray()))
            {
                resources.Add(resource);
            }

            return resources;
        }

        private static IEnumerable<string> GetDestinations(Claim claim)
        {
            switch (claim.Type)
            {
                case Claims.Name:
                    yield return Destinations.AccessToken;

                    if (claim.Subject?.HasScope(Scopes.Profile) is true)
                    {
                        yield return Destinations.IdentityToken;
                    }

                    yield break;

                case Claims.Email:
                    yield return Destinations.AccessToken;

                    if (claim.Subject?.HasScope(Scopes.Email) is true)
                    {
                        yield return Destinations.IdentityToken;
                    }

                    yield break;

                case Claims.Role:
                    yield return Destinations.AccessToken;

                    if (claim.Subject?.HasScope(Scopes.Roles) is true)
                    {
                        yield return Destinations.IdentityToken;
                    }

                    yield break;

                case Claims.Subject:
                    yield return Destinations.AccessToken;
                    yield return Destinations.IdentityToken;
                    yield break;
            }
        }
    }
}
