using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.EntityFrameworkCore;
using RBSCore.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace RBSCore
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection")));
            //Service that will reslove following classes
            //1. UserMAnager<IdentityUer>--class to create& manage application users.
            //2. SignInManager<IdentityUer> --Managing users in signi9n process
            //services.AddDefaultIdentity<IdentityUser>(/*options => options.SignIn.RequireConfirmedAccount = true*/)
            //    .AddDefaultUI() // To render & excute the register and Login Partial View
            //    .AddEntityFrameworkStores<ApplicationDbContext>();


            //new service for user & role manager to provide user & role based security
            //Reslove following classes
            //1. UserMAnager<IdentityUer>--class to create& manage application users.
            //2. RoleMAnager<identityRole> ---Class to create manage roles
            //3. SignInManager<IdentityUser> --Manager uses sign in  process
            services.AddIdentity<IdentityUser, IdentityRole>()
                .AddDefaultUI()
                .AddEntityFrameworkStores<ApplicationDbContext>();

            services.AddAuthorization(options =>
            {
                options.AddPolicy("Read", policy =>
                {
                    policy.RequireRole("Admin", "Clerk", "Manager");
                });
                options.AddPolicy("Write", policy =>
                {
                    policy.RequireRole("Admin","Manager");
                });
            });
            services.AddControllersWithViews();
            services.AddRazorPages();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();// Basicaly use to return all static files for client side execution

            app.UseRouting();

            app.UseAuthentication();//User based security
            app.UseAuthorization(); //Role based security

            app.UseEndpoints(endpoints =>
            {
                //For MVC controllers
                endpoints.MapControllerRoute( 
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();//razor pages for web forms for identity for e.g rregister.cshtml
            });
        }
    }
}
