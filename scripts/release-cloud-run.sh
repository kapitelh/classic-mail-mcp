#!/usr/bin/env bash
set -euo pipefail
: "${PROJECT_ID:?}" "${REGION:?}" "${SERVICE:?}" "${RELEASE_IMAGE:?}"
[[ "$RELEASE_IMAGE" == *@sha256:* ]] || { echo 'A digest-pinned image is required' >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# Read only routing metadata, never environment variables or secret values.
gcloud run services describe "$SERVICE" --project="$PROJECT_ID" --region="$REGION"   --format='json(status.url,status.traffic)' > "$work/before.json"
python3 - "$work/before.json" "$work" <<'PYCODE'
import json, pathlib, sys
s=json.load(open(sys.argv[1]))['status']; p=pathlib.Path(sys.argv[2])
p.joinpath('url').write_text(s['url'])
routes={}
for t in s['traffic']:
    if t.get('percent',0):
        revision=t.get('revisionName')
        if not revision: raise SystemExit('Cannot identify rollback revision')
        routes[revision]=routes.get(revision,0)+t['percent']
if sum(routes.values()) != 100: raise SystemExit('Expected a complete existing traffic allocation')
p.joinpath('traffic').write_text(','.join(f'{r}={v}' for r,v in routes.items()))
PYCODE
base_url="$(cat "$work/url")"
previous="$(cat "$work/traffic")"
tag="candidate-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"
# Update only the image; preserve service account, secrets, access mode, storage and limits.
gcloud run services update "$SERVICE" --project="$PROJECT_ID" --region="$REGION"   --image="$RELEASE_IMAGE" --no-traffic --tag="$tag" --quiet
gcloud run services describe "$SERVICE" --project="$PROJECT_ID" --region="$REGION"   --format='json(status.traffic)' > "$work/candidate.json"
read -r revision candidate_url < <(python3 - "$work/candidate.json" "$tag" <<'PYCODE'
import json,sys
for t in json.load(open(sys.argv[1]))['status']['traffic']:
    if t.get('tag') == sys.argv[2]:
        print(t['revisionName'],t['url']); break
else: raise SystemExit('Candidate route missing')
PYCODE
)
node scripts/verify-deployment.mjs "$candidate_url"
gcloud run services update-traffic "$SERVICE" --project="$PROJECT_ID" --region="$REGION"   --to-revisions="$revision=100" --quiet
if ! node scripts/verify-deployment.mjs "$base_url"; then
  echo 'Post-deployment verification failed; restoring prior traffic' >&2
  gcloud run services update-traffic "$SERVICE" --project="$PROJECT_ID" --region="$REGION"     --to-revisions="$previous" --quiet
  exit 1
fi
gcloud run services update-traffic "$SERVICE" --project="$PROJECT_ID" --region="$REGION"   --remove-tags="$tag" --quiet
printf 'Deployed revision %s at %s\n' "$revision" "$base_url"
