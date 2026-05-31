using OpenIddict.Abstractions;
using static System.Net.Mime.MediaTypeNames;

namespace FamilyChat.SSO.ServiceCollectionExtensions
{
    public class OpenIddictSeeder : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;

        public OpenIddictSeeder(IServiceProvider provider) => _serviceProvider = provider ?? throw new ArgumentNullException(nameof(IServiceProvider));
        public async Task StartAsync(CancellationToken cancellationToken)
        {
            await using var scope = _serviceProvider.CreateAsyncScope();
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var application = await manager.FindByClientIdAsync("fr_ang_cl");
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = "fr_ang_cl",
                ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
                ClientType = OpenIddictConstants.ClientTypes.Public,
                DisplayName = "FamilyChat Angular Client",
                RedirectUris =
                    {
                        new Uri("https://localhost:4200/signin-callback-oidc")
                    },
                Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Authorization,
                        OpenIddictConstants.Permissions.Endpoints.Token,

                        OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                        OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                        OpenIddictConstants.Permissions.ResponseTypes.Code,

                        OpenIddictConstants.Permissions.Scopes.Email,
                        OpenIddictConstants.Permissions.Scopes.Profile,
                    },
                Requirements = { OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange }
            };

            if (application is null)
            {
                await manager.CreateAsync(descriptor, cancellationToken);
            }
            else
            {
                await manager.UpdateAsync(application, descriptor, cancellationToken);
            }
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
