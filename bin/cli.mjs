#!/usr/bin/env node
// malinois-scan — passive security check for a deployed web app.
//
// Boundaries (identical to the hosted service, deliberately):
//   - Passive only: plain GET requests any visitor could make. No exploitation,
//     no injection, no brute force, no load testing.
//   - Ownership required: you must pass --i-own-this. This tool is for checking
//     apps you control, not for probing strangers.
//   - Never prints a raw secret: findings show a masked form only.

import { runScan } from '../src/scanner.js';
import { explain, severityRank, severityWord } from '../src/explain.js';

const HELP = `
malinois-scan — passive security check for a deployed web app

USAGE
  npx malinois-scan <url> --i-own-this [options]

OPTIONS
  --i-own-this        Required. Confirms you own the app or have permission.
  --json              Machine-readable output (for CI).
  --fail-on <level>   Exit 1 when a finding at/above this level is found.
                      critical | high | medium | low   (default: high)
  --no-color          Disable ANSI colour.
  -h, --help          Show this help.

EXAMPLES
  npx malinois-scan https://my-app.example --i-own-this
  npx malinois-scan https://my-app.example --i-own-this --json --fail-on critical

WHAT IT CHECKS
  Publicly readable databases (Supabase / Firebase), secrets left in client
  bundles (Stripe / OpenAI / Anthropic / AWS / private keys / service_role),
  exposed files (.env, .git, source maps), permissive CORS, mixed content,
  and missing security headers.

Continuous monitoring (re-check on every deploy, alert on new leaks):
  https://malinois.app
`;

const argv = process.argv.slice(2);
if (argv.length === 0 || argv.includes('-h') || argv.includes('--help')) {
  process.stdout.write(HELP);
  process.exit(argv.length === 0 ? 1 : 0);
}

const flag = (name) => argv.includes(name);
const valueOf = (name, fallback) => {
  const i = argv.indexOf(name);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : fallback;
};

const url = argv.find((a) => !a.startsWith('-') && argv[argv.indexOf(a) - 1] !== '--fail-on');
const asJson = flag('--json');
const failOn = String(valueOf('--fail-on', 'high')).toLowerCase();
const useColor = !flag('--no-color') && process.stdout.isTTY && !process.env.NO_COLOR;

if (!url) {
  process.stderr.write('error: no URL given\n' + HELP);
  process.exit(1);
}
if (!flag('--i-own-this')) {
  process.stderr.write(
    'error: --i-own-this is required.\n\n' +
    'This tool only checks apps you own or have permission to test.\n' +
    'Scanning someone else\'s app without permission is not supported.\n'
  );
  process.exit(1);
}
if (!['critical', 'high', 'medium', 'low'].includes(failOn)) {
  process.stderr.write(`error: --fail-on must be critical|high|medium|low (got "${failOn}")\n`);
  process.exit(1);
}

const c = (code, s) => (useColor ? `[${code}m${s}[0m` : s);
const SEV_COLOR = { critical: '31;1', high: '31', medium: '33', low: '90', info: '90' };
const GRADE_COLOR = { A: '32;1', B: '32', C: '33', D: '33;1', E: '31', F: '31;1' };

let result;
try {
  result = await runScan(url);
} catch (err) {
  process.stderr.write(`error: scan failed — ${err?.message || err}\n`);
  process.exit(2);
}

if (!result.ok) {
  const msg = result.error === 'unreachable'
    ? `could not reach ${url}`
    : result.error === 'blocked_target'
      ? 'that address cannot be scanned (private, loopback, or metadata address)'
      : `scan failed (${result.error || 'unknown'})`;
  if (asJson) process.stdout.write(JSON.stringify({ ok: false, error: result.error, url }) + '\n');
  else process.stderr.write(`error: ${msg}\n`);
  process.exit(2);
}

// scan_meta is an internal transparency note, not a security finding
const findings = (result.findings || [])
  .filter((f) => f.category !== 'scan_meta')
  .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

if (asJson) {
  process.stdout.write(JSON.stringify({
    ok: true,
    url,
    host: result.host,
    platform: result.platform,
    grade: result.grade,
    score: result.score,
    limited: !!result.limited,
    findings: findings.map((f) => {
      const ex = explain(f.rule_id, 'en');
      return {
        rule_id: f.rule_id,
        severity: f.severity,
        category: f.category,
        title: ex ? ex.title : f.label,
        what_it_means: ex ? ex.what : undefined,
        what_to_do: ex ? ex.fix : undefined,
        evidence: f.evidence_redacted,
      };
    }),
  }, null, 2) + '\n');
} else {
  const g = result.grade;
  process.stdout.write(`\n  ${c(GRADE_COLOR[g] || '0', `Grade ${g}`)}  ${result.score}/100   ${c('90', result.host)}\n`);
  if (result.limited) {
    process.stdout.write(`  ${c('33', 'Limited scan')} — this app renders in the browser and hid its backend from a\n`);
    process.stdout.write(`  passive check, so a clean grade here is not a clean bill of health.\n`);
  }
  process.stdout.write('\n');

  if (findings.length === 0) {
    process.stdout.write(`  ${c('32', 'No issues found in the passive checks.')}\n`);
    process.stdout.write(`  ${c('90', 'Keep checking after each deploy — new code can introduce new risks.')}\n\n`);
  } else {
    process.stdout.write(`  ${findings.length} issue${findings.length === 1 ? '' : 's'} found\n\n`);
    for (const f of findings) {
      const ex = explain(f.rule_id, 'en');
      const sev = severityWord(f.severity, 'en').toUpperCase();
      process.stdout.write(`  ${c(SEV_COLOR[f.severity] || '0', sev.padEnd(8))} ${ex ? ex.title : f.label}\n`);
      if (ex) {
        process.stdout.write(`  ${' '.repeat(8)} ${c('90', 'What it means:')} ${ex.what}\n`);
        process.stdout.write(`  ${' '.repeat(8)} ${c('90', 'What to do:')}    ${ex.fix}\n`);
      }
      process.stdout.write('\n');
    }
  }
  process.stdout.write(`  ${c('90', 'Passive external check, not a penetration test.')}\n`);
  process.stdout.write(`  ${c('90', 'Continuous monitoring on every deploy: https://malinois.app')}\n\n`);
}

const threshold = severityRank(failOn);
const worst = findings.length ? severityRank(findings[0].severity) : 99;
process.exit(worst <= threshold ? 1 : 0);
