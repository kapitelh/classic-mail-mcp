# CI/CD for the existing Cloud Run service

Pull requests run the Linux/macOS test matrix and Docker smoke tests. A push to main runs the same checks, then the production deployment workflow. No deployment credentials are available to pull-request jobs. Actions are pinned to commit hashes. Production deployments are serialized and never cancelled mid-rollout.

The release job builds and smoke-tests its image before Google authentication, scans OS and application packages with Trivy (HIGH/CRITICAL blocks release), pushes to Artifact Registry, and deploys by immutable digest. It updates only the image of an existing Cloud Run service; secrets, runtime identity, storage and access mode are preserved. A tagged revision receives no production traffic until health and anonymous-access checks pass. Failed checks after promotion restore the previous traffic allocation. Failed candidates remain available for diagnosis; remove their tags after investigation.

## One-time activation

Create a GitHub environment named `production`, restricted to the `main` branch. For fully automatic releases do not require an environment reviewer. Protect main with required PR review and the test/docker checks; disallow force pushes and deletion. Restrict changes to workflows and release scripts to trusted maintainers.

Set these repository or production environment variables (none are passwords):

| Variable                       | Value                                                                          |
| ------------------------------ | ------------------------------------------------------------------------------ |
| GCP_PROJECT_ID                 | Existing Google Cloud project ID                                               |
| GCP_REGION                     | Existing Cloud Run region                                                      |
| CLOUD_RUN_SERVICE              | Existing service name                                                          |
| ARTIFACT_REPOSITORY            | Docker Artifact Registry repository in that region                             |
| GCP_WORKLOAD_IDENTITY_PROVIDER | projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER |
| GCP_DEPLOY_SERVICE_ACCOUNT     | Dedicated deployment account email                                             |

Use Google Workload Identity Federation with issuer `https://token.actions.githubusercontent.com`. Map `google.subject=assertion.sub`, `attribute.repository_id=assertion.repository_id`, and `attribute.repository_owner_id=assertion.repository_owner_id`. Restrict the provider condition to the numeric repository ID and owner ID, `assertion.ref == 'refs/heads/main'`, and `assertion.sub == 'repo:kapitelh/classic-mail-mcp:environment:production'`. Use the actual numeric IDs from GitHub; never rely on repository name alone. Grant the repository principal `roles/iam.workloadIdentityUser` on the dedicated deployment service account.

Grant that deployment identity Artifact Registry Writer only on the image repository, Cloud Run Developer only on the existing service, and Service Account User only on the runtime service account. Keep runtime and deployment identities separate. Do not grant Editor/Owner or Secret Manager payload access to CI. Enable the required Cloud Run, Artifact Registry, IAM Credentials and Security Token Service APIs. Do not add a JSON service-account key to GitHub.

Cloud Run must already be configured for OAuth and persistent Firestore. The smoke check intentionally fails on a locked or bearer-mode service. Tagged revision URLs must be reachable by the GitHub runner under the service's existing ingress policy. No configuration or IAM policy is relaxed by the release script.

## Verification and recovery

After activation, merge a reviewed PR. Inspect the `CI` run, `deploy` job and Cloud Run revision. Verification checks `/status` and rejection of anonymous MCP initialization; it does not prove provider login, authenticated OAuth or email delivery. Complete an authenticated client login and read-only mailbox check after rollout. The OAuth dependency update requires users with older tokens to sign in again.

To roll back manually use Cloud Run traffic routing to the last known good revision. Never restore old send-ledger data. If an initial update request fails or the runner is terminated after traffic promotion, inspect actual traffic before retrying; automatic rollback is guaranteed only for the handled post-promotion verification failure.

## Audit scope (2026-11-03)

Local verification covers build, formatting, source scan, OAuth public/confidential clients, invalid credentials, token-kind checks, TLS/STARTTLS, MIME reads, send deduplication and deployment orchestration with mocked commands. Real Google Cloud IAM, image scanning, Docker execution and production verification require GitHub/Cloud infrastructure and are not claimed as local successes.

The updated lockfile has no npm HIGH/CRITICAL advisories. Six moderate dependency findings remain in the Firestore API dependency chain (glob/minimatch/rimraf and dependents). `npm audit fix --dry-run` proposes no changes. These are retained transparently rather than forcing incompatible major overrides or suppressing advisories. Review upstream updates regularly.
