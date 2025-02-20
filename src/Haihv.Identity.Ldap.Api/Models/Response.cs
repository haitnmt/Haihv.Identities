namespace Haihv.Identity.Ldap.Api.Models;

public class Response<T>
{
    public T? Value { get; set; }
    public string? ErrorMsg { get; set; }

    public Response()
    {
    }
    public Response(T value)
    {
        Value = value;
    }
    public Response(string errorMsg)
    {
        ErrorMsg = errorMsg;
    }
}