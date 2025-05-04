using System.CommandLine;
using System.CommandLine.Binding;

namespace AppTokenFromKms.Jwt
{
    class SignerBinder: BinderBase<ISigner>
    {
        private readonly Option<string> _kmsKeyId;
        private readonly Option<string> _azureKeyVaultKeyId;

        public SignerBinder(Option<string> kmsKeyId, Option<string> azureKeyVaultKeyId)
        {
            _kmsKeyId = kmsKeyId;
            _azureKeyVaultKeyId = azureKeyVaultKeyId;
        }

        protected override ISigner GetBoundValue(BindingContext bindingContext)
        {
            var kmsKeyIdValue = bindingContext.ParseResult.GetValueForOption(_kmsKeyId);
            var azureKeyVaultKeyIdValue = bindingContext.ParseResult.GetValueForOption(_azureKeyVaultKeyId);

            if (!string.IsNullOrEmpty(kmsKeyIdValue))
            {
                return new AwsSigner(kmsKeyIdValue);
            }
            else if (!string.IsNullOrEmpty(azureKeyVaultKeyIdValue))
            {
                return new AzureSigner(azureKeyVaultKeyIdValue);
            }
            else
            {
                throw new InvalidOperationException("No valid signer found.");
            }
        }
    }
}
