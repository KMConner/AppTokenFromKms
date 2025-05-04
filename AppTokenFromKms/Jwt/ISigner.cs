namespace AppTokenFromKms.Jwt
{
    interface ISigner
    {
        Task<string> SignAsync(string payload, CancellationToken cancellationToken);
    }
}
