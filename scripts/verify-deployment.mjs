import assert from 'node:assert/strict';
const origin = new URL(process.argv[2]);
assert.equal(origin.protocol, 'https:');
const status = await fetch(new URL('/status', origin), {
  signal: AbortSignal.timeout(20000),
  redirect: 'error',
});
assert.equal(status.status, 200);
const info = await status.json();
assert.equal(info.service, 'classic-mail-mcp');
assert.equal(info.configured, true, 'Deployment must retain its configuration');
assert.equal(info.mailAccess, 'requires_oauth');
const denied = await fetch(new URL('/mcp', origin), {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
  body: JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2025-03-26',
      capabilities: {},
      clientInfo: { name: 'deployment-check', version: '1.0.0' },
    },
  }),
  signal: AbortSignal.timeout(20000),
  redirect: 'error',
});
assert.equal(denied.status, 401, 'Anonymous MCP access must be rejected');
console.log('Deployment health and anonymous-access checks passed; no mailbox accessed.');
