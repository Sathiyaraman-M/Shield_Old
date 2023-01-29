using System.ComponentModel;

namespace Shield.Models;

public enum TokenType : byte
{
    [Description("Bearer")]
    Bearer
}