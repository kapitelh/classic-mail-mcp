// Scan reachable Git blobs without printing any matched values.
// Pattern matching is a guardrail, not proof that all possible secrets are absent.
import { execFileSync } from 'node:child_process';

const git = (...args) =>
  execFileSync('git', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
const patterns = [
  /-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/,
  /GOCSPX-[A-Za-z0-9_-]{20,}/,
  /AIza[A-Za-z0-9_-]{30,}/,
  /(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})/,
  /AKIA[0-9A-Z]{16}/,
  /eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}/,
  /[a-z]+:\/\/[^\s/:]+:[^\s/@]{8,}@/i,
];
let failed = false;
let count = 0;
const objects = git('rev-list', '--objects', '--all').trim().split('\n');
for (const object of objects) {
  const sha = object.split(' ', 1)[0];
  if (git('cat-file', '-t', sha).trim() !== 'blob') continue;
  count++;
  const content = git('cat-file', 'blob', sha);
  if (patterns.some((pattern) => pattern.test(content))) {
    console.error(
      `Possible secret in Git blob ${sha}; inspect locally without publishing its contents.`,
    );
    failed = true;
  }
}
for (const path of git('ls-files', '-z').split('\0').filter(Boolean)) {
  if (
    /(?:^|\/)(?:\.secrets|\.data|data)\//.test(path) ||
    (/(?:^|\/)\.env(?:\..*)?$/.test(path) && !path.endsWith('.env.example')) ||
    /(?:\.sqlite(?:-wal|-shm)?|\.pem|\.key|\.p12|\.pfx)$/.test(path) ||
    /(?:^|\/)gha-creds-[^/]+\.json$/.test(path)
  ) {
    console.error('Private configuration or credential file must not be tracked.');
    failed = true;
  }
}
console.log(`Secret-pattern scan inspected ${count} reachable Git blobs.`);
if (failed) process.exit(1);
