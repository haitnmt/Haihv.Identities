using Haihv.Api.Identity.Ldap.Enum;

namespace Haihv.Api.Identity.Ldap.Extension;

public class ObjectClassLdap(ObjectClassTypeLdap objectClassType = ObjectClassTypeLdap.User, OperatorLdap operatorLdap = OperatorLdap.Equal)
{
    private const string
        User = "user",
        Group = "group",
        Computer = "computer";

    public AttributeWithValueLdap AttributeWithValues => GetAttributeWithValue();

    private static string GetObjectClass(ObjectClassTypeLdap objectClassType)
    {
        return objectClassType switch
        {
            ObjectClassTypeLdap.User => User,
            ObjectClassTypeLdap.Group => Group,
            ObjectClassTypeLdap.Computer => Computer,
            _ => string.Empty,
        };
    }
    private AttributeWithValueLdap GetAttributeWithValue()
    {
        return new AttributeWithValueLdap(AttributeTypeLdap.ObjectClass, [GetObjectClass(objectClassType)], operatorLdap);
    }
}