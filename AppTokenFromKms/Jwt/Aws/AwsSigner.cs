using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using System.Text;

namespace AppTokenFromKms.Jwt.Aws
{
    class AwsSigner
    {
        private readonly string _kmsKeyId;

        public AwsSigner(string kmsKeyId)
        {
            _kmsKeyId = kmsKeyId;
        }

        public async Task<string> Sign(string payload, CancellationToken cancellationToken)
        {
            // Create a KMS client
            var kmsClient = new AmazonKeyManagementServiceClient();

            // Create the request to sign the payload
            var signRequest = new SignRequest
            {
                KeyId = _kmsKeyId,
                Message = new MemoryStream(Encoding.UTF8.GetBytes(payload)),
                SigningAlgorithm = SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256,
                MessageType = MessageType.RAW
            };

            // Sign the payload using KMS
            var signResponse = await kmsClient.SignAsync(signRequest, cancellationToken);

            // Return the signature as a base64 string
            return Convert.ToBase64String(signResponse.Signature.ToArray())
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }
    }
}
