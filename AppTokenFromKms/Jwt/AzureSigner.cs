using Azure.Security.KeyVault;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Identity;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.Intrinsics.Arm;

namespace AppTokenFromKms.Jwt
{
    public class AzureSigner : ISigner
    {
        private readonly string _keyVaultKeyId;

        public AzureSigner(string keyVaultKeyId)
        {
            _keyVaultKeyId = keyVaultKeyId;
        }

        public async Task<string> SignAsync(string payload, CancellationToken cancellationToken)
        {
            var keyId = new Uri(_keyVaultKeyId);
            string vaultId = keyId.GetLeftPart(UriPartial.Authority);
            string keyName = keyId.Segments[2].TrimEnd('/');

            var keyClient = new KeyClient(new Uri(vaultId), new DefaultAzureCredential());
            Console.WriteLine($"Key Name: {keyName}");

            var cryptoClient = keyClient.GetCryptographyClient(keyName);
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(payload));

            var signResult = await cryptoClient.SignAsync(SignatureAlgorithm.RS256, hash, cancellationToken);
            return Convert.ToBase64String(signResult.Signature).TrimEnd('=')    
                .Replace('+', '-')
                .Replace('/', '_');
        }
    }
}
