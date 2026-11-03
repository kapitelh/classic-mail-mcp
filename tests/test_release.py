"""Exercise release orchestration without cloud credentials or network access."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReleaseTests(unittest.TestCase):
    def run_release(self, failure="", image="example/image@sha256:" + "a" * 64):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            mock = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args=sys.argv[1:]
p=Path(os.environ['MOCK_DIR'])
with (p/'calls').open('a') as f: f.write(json.dumps([Path(sys.argv[0]).name]+args)+'\\n')
if Path(sys.argv[0]).name == 'node':
    candidate='candidate.example' in args[-1]
    sys.exit(1 if os.environ.get('FAIL') == ('candidate' if candidate else 'production') else 0)
if 'describe' in args:
    before=not (p/'described').exists(); (p/'described').touch()
    traffic=[{'revisionName':'old-revision','percent':100}]
    if not before: traffic.append({'revisionName':'new-revision','tag':'candidate-123-1','url':'https://candidate.example'})
    print(json.dumps({'status':{'url':'https://production.example','traffic':traffic}}))
'''
            for name in ("gcloud", "node"):
                path = directory / name
                path.write_text(mock)
                path.chmod(0o700)
            env = {**os.environ, "PATH": tmp + os.pathsep + os.environ["PATH"],
                   "MOCK_DIR": tmp, "FAIL": failure, "PROJECT_ID": "fixture-project",
                   "REGION": "europe-west1", "SERVICE": "fixture", "RELEASE_IMAGE": image,
                   "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}
            result = subprocess.run(["bash", str(ROOT / 'scripts/release-cloud-run.sh')],
                                    env=env, capture_output=True, text=True)
            calls = [json.loads(line) for line in (directory / 'calls').read_text().splitlines()] if (directory / 'calls').exists() else []
            return result, calls

    def test_promotes_only_after_candidate_check(self):
        result, calls = self.run_release()
        self.assertEqual(result.returncode, 0, result.stderr)
        check = next(i for i,c in enumerate(calls) if c[0] == 'node')
        promote = next(i for i,c in enumerate(calls) if '--to-revisions=new-revision=100' in c)
        self.assertLess(check, promote)
        update = next(c for c in calls if 'update' in c)
        self.assertIn('--no-traffic', update)
        self.assertFalse(any('set-env' in arg or 'set-secret' in arg for arg in update))

    def test_candidate_failure_preserves_traffic(self):
        result, calls = self.run_release('candidate')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any('update-traffic' in c for c in calls))

    def test_post_promotion_failure_rolls_back(self):
        result, calls = self.run_release('production')
        self.assertNotEqual(result.returncode, 0)
        routes = [c for c in calls if 'update-traffic' in c]
        self.assertIn('--to-revisions=new-revision=100', routes[0])
        self.assertIn('--to-revisions=old-revision=100', routes[1])

    def test_mutable_image_is_rejected_before_cloud_access(self):
        result, calls = self.run_release(image='example/image:latest')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])
