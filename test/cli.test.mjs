// Contract tests for the CLI's safety boundaries and CI exit codes.
// These are the promises the README makes; if one breaks, the tool is unsafe
// or unusable in CI, so they are checked on every push.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createServer } from 'node:http';

const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'cli.mjs');

function run(args) {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args], { timeout: 60000 }, (err, stdout, stderr) => {
      resolve({ code: err?.code ?? 0, stdout, stderr });
    });
  });
}

// A deliberately leaky fixture app, served locally, so the critical-path checks
// are exercised without depending on the internet or a third party.
function leakyServer() {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const serviceJwt = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ role: 'service_role', iss: 'supabase' })}.c2lnbmF0dXJlX3BsYWNlaG9sZGVy`;
  const server = createServer((req, res) => {
    if (req.url.startsWith('/.env')) {
      res.writeHead(200, { 'content-type': 'text/plain' });
      return res.end('SUPABASE_SERVICE_KEY=abc123\nDB_PASSWORD=hunter2\n');
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<!doctype html><html><head><title>Leaky</title></head><body>
<div id="root">demo</div><script>const admin="${serviceJwt}";</script>
<p>Some real content so this is not treated as an empty shell. Lorem ipsum dolor sit amet
consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna.</p>
</body></html>`);
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

test('refuses to scan without an ownership attestation', async () => {
  const r = await run(['https://example.com']);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /--i-own-this is required/);
});

test('refuses private, loopback and cloud-metadata targets (no SSRF proxy)', async () => {
  for (const target of ['http://169.254.169.254/', 'http://127.0.0.1/', 'http://10.0.0.1/']) {
    const r = await run([target, '--i-own-this']);
    assert.equal(r.code, 2, `${target} should be refused`);
    assert.match(r.stderr, /cannot be scanned/);
  }
});

test('emits valid JSON with plain-language help per finding', async () => {
  const r = await run(['https://example.com', '--i-own-this', '--json']);
  const parsed = JSON.parse(r.stdout);
  assert.equal(parsed.ok, true);
  assert.match(parsed.grade, /^[A-F]$/);
  assert.ok(Array.isArray(parsed.findings));
  for (const f of parsed.findings) {
    assert.ok(f.rule_id && f.severity && f.title, 'finding needs rule_id, severity, title');
  }
});

test('--fail-on controls the CI exit code', async () => {
  const strict = await run(['https://example.com', '--i-own-this', '--fail-on', 'low', '--no-color']);
  assert.equal(strict.code, 1, 'low threshold should fail on any finding');
  const lenient = await run(['https://example.com', '--i-own-this', '--fail-on', 'critical', '--no-color']);
  assert.equal(lenient.code, 0, 'example.com has no critical finding');
});

test('rejects an invalid --fail-on level', async () => {
  const r = await run(['https://example.com', '--i-own-this', '--fail-on', 'banana']);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /must be critical\|high\|medium\|low/);
});

test('the ownership/SSRF guard still applies to a locally hosted app, and --json reports it structurally', async () => {
  // A deliberately leaky fixture is served on loopback. The guard must win over the
  // finding: refusing to scan a private address matters more than catching its leak.
  const { server, port } = await leakyServer();
  try {
    const r = await run([`http://127.0.0.1:${port}/`, '--i-own-this', '--json']);
    assert.equal(r.code, 2);
    const parsed = JSON.parse(r.stdout);
    assert.equal(parsed.ok, false);
    assert.equal(parsed.error, 'blocked_target');
    assert.doesNotMatch(r.stdout, /hunter2|SUPABASE_SERVICE_KEY/, 'must never echo fixture secrets');
  } finally {
    server.close();
  }
});

test('help text is available and exits cleanly', async () => {
  const r = await run(['--help']);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /malinois-scan/);
  assert.match(r.stdout, /--i-own-this/);
});
