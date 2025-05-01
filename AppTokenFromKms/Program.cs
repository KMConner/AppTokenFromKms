using System.CommandLine;
using System.CommandLine.Parsing;
using AppTokenFromKms.Handlers;
using AppTokenFromKms.Jwt;

namespace AppTokenFromKms
{
    public class Program
    {
        static void Main(string[] args)
        {
            var clientIdOption = new Option<string>("--client-id", "The client ID for the GitHub App") { IsRequired = true };
            var kmsKeyIdOption = new Option<string>("--aws-kms-key-arn", "KMS Key ID") { IsRequired = false };
            var azureKeyVaultKeyIdentifier = new Option<string>("--azure-key-vault-key-id", "Azure Key Vault Key Identifier") { IsRequired = false };
            var installationIdOption = new Option<long>("--installation-id", "Installation ID") { IsRequired = true };
            var rootCmd = new RootCommand("Create a new token for GitHub Apps with key stored in AWS KMS or Azure KeyVault");

            var listInstallationCmd = new Command("list-installations", "List all installations for the GitHub App");
            rootCmd.AddCommand(listInstallationCmd);
            var issueCmd = new Command("issue", "Create a new token for GitHub Apps with key stored in AWS KMS or Azure KeyVault");
            issueCmd.AddOption(installationIdOption);
            rootCmd.AddCommand(issueCmd);
            rootCmd.AddGlobalOption(clientIdOption);
            rootCmd.AddGlobalOption(kmsKeyIdOption);
            rootCmd.AddGlobalOption(azureKeyVaultKeyIdentifier);

            listInstallationCmd.SetHandler(CommandHandlers.ListInstallations, clientIdOption, new SignerBinder(kmsKeyIdOption, azureKeyVaultKeyIdentifier));
            issueCmd.SetHandler(CommandHandlers.IssueToken, clientIdOption, new SignerBinder(kmsKeyIdOption, azureKeyVaultKeyIdentifier), installationIdOption);

            ValidateSymbolResult<CommandResult> keySpecificationValidation = cmd =>
            {
                if (!(string.IsNullOrEmpty(cmd.GetValueForOption(kmsKeyIdOption)) ^ string.IsNullOrEmpty(cmd.GetValueForOption(azureKeyVaultKeyIdentifier))))
                {
                    cmd.ErrorMessage = "Either --aws-kms-key-arn or --azure-key-vault-key-id must be provided.";
                    return;
                }
            };
            issueCmd.AddValidator(keySpecificationValidation);
            listInstallationCmd.AddValidator(keySpecificationValidation);

            rootCmd.Invoke(args);
        }
    }
}
