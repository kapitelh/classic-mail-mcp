#!/usr/bin/env bash
# One-time IAM bootstrap. Review and explicitly approve these grants before running.
# Run as an administrator in Cloud Shell, never as part of the deployment workflow.
# Deliberately stops if a named identity already exists: inspect partial setup first.
set -euo pipefail

project=kapitelh-931c3
number=1014099796358
region=europe-west6
pool=github-classic-mail
account=github-classic-mail-deploy
email="${account}@${project}.iam.gserviceaccount.com"
runtime="classic-mail-mcp@${project}.iam.gserviceaccount.com"

[[ "$(gcloud projects describe "$project" --format='value(projectNumber)')" == "$number" ]]
gcloud run services describe classic-mail-mcp --project="$project" --region="$region" --format='value(metadata.name)'
gcloud artifacts repositories describe cloud-run-source-deploy --project="$project" --location="$region" --format='value(name)'

gcloud services enable iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com run.googleapis.com artifactregistry.googleapis.com --project="$project"
gcloud iam service-accounts create "$account" --project="$project" --display-name='ClassicMail GitHub deployment'
gcloud iam workload-identity-pools create "$pool" --project="$project" --location=global --display-name='ClassicMail GitHub'
gcloud iam workload-identity-pools providers create-oidc github \
  --project="$project" --location=global --workload-identity-pool="$pool" \
  --issuer-uri=https://token.actions.githubusercontent.com \
  --attribute-mapping='google.subject=assertion.sub,attribute.repository_id=assertion.repository_id,attribute.repository_owner_id=assertion.repository_owner_id' \
  --attribute-condition="assertion.repository_id == '1423706964' && assertion.repository_owner_id == '106238865' && assertion.ref == 'refs/heads/main' && assertion.sub == 'repo:kapitelh/classic-mail-mcp:environment:production'"

gcloud iam service-accounts add-iam-policy-binding "$email" --project="$project" \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/${number}/locations/global/workloadIdentityPools/${pool}/attribute.repository_id/1423706964" --condition=None
gcloud artifacts repositories add-iam-policy-binding cloud-run-source-deploy \
  --project="$project" --location="$region" --member="serviceAccount:${email}" \
  --role=roles/artifactregistry.writer --condition=None
gcloud run services add-iam-policy-binding classic-mail-mcp \
  --project="$project" --region="$region" --member="serviceAccount:${email}" \
  --role=roles/run.developer --condition=None
gcloud iam service-accounts add-iam-policy-binding "$runtime" --project="$project" \
  --member="serviceAccount:${email}" --role=roles/iam.serviceAccountUser --condition=None

cat <<EOF
Set these GitHub production environment variables:
GCP_PROJECT_ID=$project
GCP_REGION=$region
CLOUD_RUN_SERVICE=classic-mail-mcp
ARTIFACT_REPOSITORY=cloud-run-source-deploy
GCP_WORKLOAD_IDENTITY_PROVIDER=projects/$number/locations/global/workloadIdentityPools/$pool/providers/github
GCP_DEPLOY_SERVICE_ACCOUNT=$email
EOF
