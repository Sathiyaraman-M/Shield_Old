using System.ComponentModel;

namespace Shield.Models;

internal enum AuthorizationGrantTypes : byte
{
    [Description("code")]
    Code,

    [Description("Implicit")]
    Implicit,

    [Description("ClientCredentials")]
    ClientCredentials,

    [Description("ResourceOwnerPassword")]
    ResourceOwnerPassword
}