using System.DirectoryServices.Protocols;
using Haihv.Identity.Ldap.Api.Entities;

namespace Haihv.Identity.Ldap.Api.Interfaces;

public interface ILdapContext
{
    LdapConnectionInfo LdapConnectionInfo { get; }
    LdapConnection Connection { get; }
}