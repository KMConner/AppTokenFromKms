using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace AppTokenFromKms.Jwt
{
    [JsonSourceGenerationOptions(WriteIndented = true)]
    [JsonSerializable(typeof(Dictionary<string, string>))]
    [JsonSerializable(typeof(Dictionary<string, object>))]
    [JsonSerializable(typeof(string))]
    [JsonSerializable(typeof(long))]
    internal partial class SourceGenerationContext : JsonSerializerContext
    {
    }

    static class JwtGenerator
    {
        public static string CreateJwtBase(string clientId, uint expirationInSeconds)
        {
            if (expirationInSeconds > 600)
            {
                throw new ArgumentException("Expiration time cannot exceed 600 seconds.");
            }
            var now = DateTime.UtcNow;
            var header = new Dictionary<string, string>
            {
                { "alg", "RS256" },
                { "typ", "JWT" },
            };
            var jsonHeader = JsonSerializer.Serialize(header, typeof(Dictionary<string, string>), SourceGenerationContext.Default);
            var base64Header = Convert.ToBase64String(Encoding.UTF8.GetBytes(jsonHeader))
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            var payload = new Dictionary<string, object>
            {
                { "iat", new DateTimeOffset(now).AddSeconds(-60).ToUnixTimeSeconds() },
                { "exp", new DateTimeOffset(now).AddSeconds(expirationInSeconds).ToUnixTimeSeconds() },
                { "iss", clientId }
            };
            var jsonPayload = JsonSerializer.Serialize(payload, typeof(Dictionary<string, object>), SourceGenerationContext.Default);
            var base64Payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(jsonPayload))
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            return $"{base64Header}.{base64Payload}";
        }
    }
}
