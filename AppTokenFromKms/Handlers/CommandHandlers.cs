using AppTokenFromKms.Jwt;
using Octokit;

namespace AppTokenFromKms.Handlers
{
    static class CommandHandlers
    {
        public static async Task ListInstallations(string clientId, ISigner signer)
        {
            var jwt = await GetJwtAsync(clientId, signer, CancellationToken.None);
            GitHubClient githubClient = new GitHubClient(new ProductHeaderValue("AppTokenFromKms"))
            {
                Credentials = new Credentials(jwt, AuthenticationType.Bearer)
            };
            var installations = await githubClient.GitHubApps.GetAllInstallationsForCurrent();
            foreach (var installation in installations)
            {
                Console.WriteLine($"Installation ID: {installation.Id}, Account: {installation.Account.Login}");
            }
        }

        public static async Task IssueToken(string clientId, ISigner signer, long installationId)
        {
              var jwt = await GetJwtAsync(clientId, signer, CancellationToken.None);
            GitHubClient githubClient = new GitHubClient(new ProductHeaderValue("AppTokenFromKms"))
            {
                Credentials = new Credentials(jwt, AuthenticationType.Bearer)
            };
            var installations = await githubClient.GitHubApps.CreateInstallationToken(installationId);
            Console.WriteLine($"Token: {installations.Token}");
        }

        private static async Task<string> GetJwtAsync(string clientId, ISigner signer, CancellationToken cancellationToken)
        {
            var baseString = JwtGenerator.CreateJwtBase(clientId, 600);
            var signature = await signer.SignAsync(baseString, cancellationToken);
            return $"{baseString}.{signature}";
        }
    }
}