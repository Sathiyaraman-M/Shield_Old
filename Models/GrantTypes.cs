using Shield.Common;

namespace Shield.Models;

public class GrantTypes
{
    public static IList<string> Code =>
        new[] { AuthorizationGrantTypes.Code.GetEnumDescription() };

    public static IList<string> Implicit =>
        new[] { AuthorizationGrantTypes.Implicit.GetEnumDescription() };
    public static IList<string> ClientCredentials =>
        new[] { AuthorizationGrantTypes.ClientCredentials.GetEnumDescription() };
    public static IList<string> ResourceOwnerPassword =>
        new[] { AuthorizationGrantTypes.ResourceOwnerPassword.GetEnumDescription() };
}