using Shield.OAuthRequest;
using Shield.OAuthResponse;

namespace Shield.Services;

public interface IAuthorizeResultService
{
    AuthorizeResponse AuthorizeRequest(IHttpContextAccessor httpContextAccessor, AuthorizationRequest authorizationRequest);
    TokenResponse GenerateToken(IHttpContextAccessor httpContextAccessor);
}