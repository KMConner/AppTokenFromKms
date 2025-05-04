using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using System.Text;

namespace AppTokenFromKms.Jwt
{
    class AwsSigner :ISigner
    {
        private readonly string _kmsKeyId;
        private readonly AmazonKeyManagementServiceClient _kmsClient;

        public AwsSigner(string kmsKeyId)
        {
            _kmsKeyId = kmsKeyId;
            _kmsClient = new AmazonKeyManagementServiceClient();
        }

        public async Task<string> SignAsync(string payload, CancellationToken cancellationToken)
        {
            // Create the request to sign the payload
            var signRequest = new SignRequest
            {
                KeyId = _kmsKeyId,
                Message = new MemoryStream(Encoding.UTF8.GetBytes(payload)),
                SigningAlgorithm = SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256,
                MessageType = MessageType.RAW
            };

            // Sign the payload using KMS
            var signResponse = await _kmsClient.SignAsync(signRequest, cancellationToken);

            // Return the signature as a base64 string
            return Convert.ToBase64String(signResponse.Signature.ToArray())
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }
    }
}
