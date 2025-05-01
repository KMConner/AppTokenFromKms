using System.CommandLine;
using System.Runtime.CompilerServices;
using AppTokenFromKms.Jwt;
using AppTokenFromKms.Jwt.Aws;

namespace AppTokenFromKms
{
    public class Program
    {
        static void Main(string[] args)
        {
            var clientIdOption = new Option<string>("--client-id", "The client ID for the GitHub App") { IsRequired = true };
            var kmsKeyIdOption = new Option<string>("--aws-kms-key-arn", "KMS Key ID") { IsRequired = false };
            var azureKeyVaultKeyIdentifier = new Option<string>("--azure-key-vault-key-id", "Azure Key Vault Key Identifier") { IsRequired = false };
            var rootCmd = new RootCommand("Create a new token for GitHub Apps with key stored in AWS KMS or Azure KeyVault");

            var listInstallationCmd = new Command("list-installations", "List all installations for the GitHub App")
            {
                clientIdOption,
                kmsKeyIdOption,
                azureKeyVaultKeyIdentifier,
            };
            rootCmd.AddCommand(listInstallationCmd);

            listInstallationCmd.SetHandler((clientId, kmsKeyId, azureKeyVaultKeyId) =>
            {
                var baseString = JwtGenerator.CreateJwtBase(clientId, 600);
                AwsSigner signer = new AwsSigner(kmsKeyId);
                var signature = signer.Sign(baseString, CancellationToken.None).Result;
                Console.WriteLine($"JWT: {baseString}.{signature}"); 

                Console.WriteLine($"Listing installations for client ID: {clientId} with KMS Key ID: {kmsKeyId} and Azure Key Vault Key ID: {azureKeyVaultKeyId}");
            }, clientIdOption, kmsKeyIdOption, azureKeyVaultKeyIdentifier);

            var issueCmd = new Command("issue", "Create a new token for GitHub Apps with key stored in AWS KMS or Azure KeyVault")
            {
                clientIdOption,
                kmsKeyIdOption,
                azureKeyVaultKeyIdentifier,
            };
            rootCmd.AddCommand(issueCmd);

            rootCmd.Invoke(args);
        }
    }
}
