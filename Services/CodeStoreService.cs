using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Shield.Models;

namespace Shield.Services;

public class CodeStoreService : ICodeStoreService
{
    private readonly ConcurrentDictionary<string, AuthorizationCode> _codeIssued = new ConcurrentDictionary<string, AuthorizationCode>();
    private readonly ClientStore _clientStore = new ClientStore();
    
    public string GenerateAuthorizationCode(string clientId, IList<string> requestedScope)
    {
        var client = _clientStore.Clients.FirstOrDefault(x => x.ClientId == clientId);

        if (client == null) 
            return null;
        
        var code = Guid.NewGuid().ToString();

        var authorizationCode = new AuthorizationCode
        {
            ClientId = clientId,
            RedirectUri = client.RedirectUri,
            RequestedScopes = requestedScope,
        };

        // then store the code is the Concurrent Dictionary
        _codeIssued[code] = authorizationCode;

        return code;
    }

    public AuthorizationCode GetClientDataByCode(string key)
    {
        return _codeIssued.TryGetValue(key, out var authorizationCode) ? authorizationCode : null;
    }

    public AuthorizationCode RemoveClientDataByCode(string key)
    {
        _codeIssued.TryRemove(key, out var authorizationCode);
        return null;
    }
    
    public AuthorizationCode UpdatedClientDataByCode(string key, IList<string> requestdScopes, string userName, string password = null, string nonce = null)
        {
            var oldValue = GetClientDataByCode(key);

            if (oldValue != null)
            {
                // check the requested scopes with the one that are stored in the Client Store 
                var client = _clientStore.Clients.Where(x => x.ClientId == oldValue.ClientId).FirstOrDefault();

                if (client != null)
                {
                    var clientScope = (from m in client.AllowedScopes
                                       where requestdScopes.Contains(m)
                                       select m).ToList();

                    if (!clientScope.Any())
                        return null;

                    AuthorizationCode newValue = new AuthorizationCode
                    {
                        ClientId = oldValue.ClientId,
                        CreationTime = oldValue.CreationTime,
                        IsOpenId = requestdScopes.Contains("openId") || requestdScopes.Contains("profile"),
                        RedirectUri = oldValue.RedirectUri,
                        RequestedScopes = requestdScopes,
                        Nonce = nonce
                    };


                    // ------------------ I suppose the user name and password is correct  -----------------
                    var claims = new List<Claim>();



                    if (newValue.IsOpenId)
                    {
                        // TODO
                        // Add more claims to the claims

                    }

                    var claimIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    newValue.Subject = new ClaimsPrincipal(claimIdentity);
                    // ------------------ -----------------------------------------------  -----------------

                    var result = _codeIssued.TryUpdate(key, newValue, oldValue);

                    if (result)
                        return newValue;
                    return null;
                }
            }
            return null;
        }
}