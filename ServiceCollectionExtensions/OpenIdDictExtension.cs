using FamilyChat.SSO.DBContext;
using Microsoft.EntityFrameworkCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace FamilyChat.SSO.ServiceCollectionExtensions
{
    internal static class OpenIddictExtension
    {
        internal static IServiceCollection ConfigureOpenIddict(this IServiceCollection services, ConfigurationManager configuration)
        {
            services.AddDbContext<AppDbContext>(options =>
            {
                // Configure Entity Framework Core to use Microsoft SQL Server.
                options.UseNpgsql(configuration.GetConnectionString("postgresql"));

                // Register the entity sets needed by OpenIddict.
                // Note: use the generic overload if you need to replace the default OpenIddict entities.
                options.UseOpenIddict();
            });
            services.AddOpenIddict()
                    .AddCore(options =>
                    {
                        // Configure OpenIddict to use the Entity Framework Core stores and models.
                        // Note: call ReplaceDefaultEntities() to replace the default entities.
                        options.UseEntityFrameworkCore()
                            .UseDbContext<AppDbContext>();
                    })
                    // Register the OpenIddict server components.
                    .AddServer(options =>
                    {
                        // Enable the authorization, logout, token and userinfo endpoints.
                        options.SetAuthorizationEndpointUris("connect/authorize")
                               .SetEndSessionEndpointUris("connect/logout")
                               .SetTokenEndpointUris("connect/token")
                               .SetUserInfoEndpointUris("connect/userinfo");

                        // Mark the "email", "profile" and "roles" scopes as supported scopes.
                        options.RegisterScopes(
                            Scopes.OpenId,
                            Scopes.Email,
                            Scopes.Profile,
                            Scopes.Roles,
                            Scopes.Phone,
                            Scopes.OfflineAccess);

                        // Enable the authorization and refresh token flows.
                        options.AllowAuthorizationCodeFlow()
                               .AllowRefreshTokenFlow();

                        // Enabling PKCE enforcement at the global level
                        options.RequireProofKeyForCodeExchange();

                        // Register the signing and encryption credentials.
                        options.AddDevelopmentEncryptionCertificate()
                               .AddDevelopmentSigningCertificate();

                        // Register the ASP.NET Core host and configure the ASP.NET Core options.
                        options.UseAspNetCore()
                               .EnableAuthorizationEndpointPassthrough()
                               .EnableEndSessionEndpointPassthrough()
                               .EnableUserInfoEndpointPassthrough()
                               .EnableStatusCodePagesIntegration();
                    })
                    .AddValidation(options =>
                    {
                        options.UseLocalServer();
                        options.UseAspNetCore();
                    });

            services.AddHostedService<OpenIddictSeeder>();

            return services;
        }

    }
}
