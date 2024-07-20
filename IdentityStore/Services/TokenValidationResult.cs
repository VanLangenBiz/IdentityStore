namespace IdentityStore.Services
{
    public enum TokenValidationResult
    {
        Valid,
        Expired,
        InvalidSignature,
        InvalidIssuer,
        InvalidAudience,
        OtherError
    }
}