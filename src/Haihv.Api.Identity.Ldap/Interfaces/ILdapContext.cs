using System.DirectoryServices.Protocols;
using Haihv.Api.Identity.Ldap.Entities;

namespace Haihv.Api.Identity.Ldap.Interfaces;

public interface ILdapContext
{
    LdapConnectionInfo LdapConnectionInfo { get; }
    LdapConnection Connection { get; }
}