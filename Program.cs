using Shield.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication().AddCookie();
builder.Services.AddSingleton<ICodeStoreService, CodeStoreService>();
builder.Services.AddScoped<IAuthorizeResultService, AuthorizeResultService>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddControllersWithViews();

var app = builder.Build();

app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();
app.MapDefaultControllerRoute();

app.Run();