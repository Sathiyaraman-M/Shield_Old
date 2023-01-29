namespace Shield.Models;

public class ClientStore
{
    public IEnumerable<Client> Clients = new[]
    {
        new Client
        {
            ClientName = "Extremis",
            ClientId = "extremis",
            ClientSecret = "CYREBYTECUYTYEUZFBRUYCFUYCYUTYCERYUCTWCJ",
            AllowedScopes = new[]{ "openid", "profile"},
            GrantType = GrantTypes.Code,
            IsActive = true,
            ClientUri = "https://localhost:7300",
            RedirectUri = "https://localhost:7300/signin-oidc"
        }
    };
}