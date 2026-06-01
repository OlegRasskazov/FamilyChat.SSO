using FamilyChat.SSO.Components;
using FamilyChat.SSO.DBContext;
using FamilyChat.SSO.ServiceCollectionExtensions;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace FamilyChat.SSO
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddRazorComponents()
                .AddInteractiveServerComponents();
            builder.Services.AddCascadingAuthenticationState();

            builder.Services.AddControllersWithViews();

            builder.Services.AddHttpContextAccessor();


            builder.Services.AddIdentity<IdentityUser, IdentityRole>()
                            .AddEntityFrameworkStores<AppDbContext>()
                            .AddDefaultTokenProviders();

            builder.Services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = "/account/login";
                options.LogoutPath = "/account/logout";
                options.AccessDeniedPath = "/account/access-denied";
            });

            builder.Services.ConfigureOpenIddict(builder.Configuration);


            var app = builder.Build();

            app.UseForwardedHeaders(new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost
            });

            if (app.Environment.IsDevelopment())
            {
                //app.UseExceptionHandler("/Error");
                using var scope = app.Services.CreateAsyncScope();
                var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                app.Logger.LogInformation($"Connectionstring: {builder.Configuration.GetConnectionString("postgresql") ?? "null"}");
                await context.Database.MigrateAsync();
            }

            app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseAntiforgery();

            app.MapControllers();

            app.MapDefaultControllerRoute();

            app.MapStaticAssets();

            app.MapRazorComponents<App>()
                .AddInteractiveServerRenderMode();

            app.Run();
        }
    }
}
