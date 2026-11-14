'use strict';
/**
 * Local self-test for the Agent Games agent endpoint.
 *
 * Starts server.js with a dummy secret, then:
 *   1. GET  /health                     -> expects { ok: true }
 *   2. POST /agent  signed preflight    -> expects { ok: true, protocolVersion: "v1" }
 *                                          and a VALID response signature
 *   3. POST /agent  signed forecast task-> expects a signed, well-formed result
 *   4. POST /agent  bad signature       -> expects HTTP 401
 *
 * Run:  node selftest.js
 */

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const path = require('node:path');

const PORT = 18741;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = 'dummy-selftest-secret-not-for-production';
const SIG_HEADER = 'x-agent-games-signature';

let failures = 0;
function check(name, cond, detail = '') {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
  if (!cond) failures++;
}

function sign(secret, raw) {
  return crypto.createHmac('sha256', secret).update(raw).digest('hex');
}

function verifyResponseSignature(secret, rawBody, headerValue) {
  if (!headerValue) return false;
  const expected = Buffer.from(sign(secret, rawBody), 'utf8');
  const provided = Buffer.from(String(headerValue).toLowerCase(), 'utf8');
  return expected.length === provided.length && crypto.timingSafeEqual(expected, provided);
}

async function waitForHealth(tries = 50) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(`${BASE}/health`);
      if (r.ok) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  return false;
}

async function postSigned(payloadObj, secret) {
  const raw = Buffer.from(JSON.stringify(payloadObj), 'utf8');
  const res = await fetch(`${BASE}/agent`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', [SIG_HEADER]: sign(secret, raw) },
    body: raw,
  });
  const rawRes = Buffer.from(await res.arrayBuffer());
  let json = null;
  try { json = JSON.parse(rawRes.toString('utf8')); } catch { /* leave null */ }
  return { status: res.status, rawRes, json, sigHeader: res.headers.get(SIG_HEADER) };
}

async function main() {
  const child = spawn(process.execPath, [path.join(__dirname, 'server.js')], {
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stderr.on('data', (d) => process.stderr.write(`[server] ${d}`));

  try {
    check('server starts and /health responds', await waitForHealth());

    // 1. health body
    const health = await (await fetch(`${BASE}/health`)).json();
    check('GET /health -> { ok: true }', health.ok === true, JSON.stringify(health));

    // 2. signed preflight
    const pre = await postSigned({ type: 'preflight' }, SECRET);
    check('preflight HTTP 200', pre.status === 200, `got ${pre.status}`);
    check(
      'preflight body is { ok: true, protocolVersion: "v1" }',
      pre.json?.ok === true && pre.json?.protocolVersion === 'v1',
      JSON.stringify(pre.json)
    );
    check(
      'preflight response signature valid',
      verifyResponseSignature(SECRET, pre.rawRes, pre.sigHeader)
    );

    // 3. signed sample task (forecast)
    const task = await postSigned(
      { type: 'forecast', id: 'selftest-task-1', question: 'Will BTC close higher tomorrow?', options: ['yes', 'no'] },
      SECRET
    );
    check('task HTTP 200', task.status === 200, `got ${task.status}`);
    check(
      'task response well-formed (ok, type=forecast, result.answer)',
      task.json?.ok === true && task.json?.type === 'forecast' && typeof task.json?.result?.answer === 'string',
      JSON.stringify(task.json)
    );
    check(
      'task response signature valid',
      verifyResponseSignature(SECRET, task.rawRes, task.sigHeader)
    );

    // 4. bad signature rejected
    const raw = Buffer.from(JSON.stringify({ type: 'preflight' }), 'utf8');
    const bad = await fetch(`${BASE}/agent`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', [SIG_HEADER]: '0'.repeat(64) },
      body: raw,
    });
    check('bad signature -> HTTP 401', bad.status === 401, `got ${bad.status}`);
  } finally {
    child.kill('SIGTERM');
  }

  console.log(failures === 0 ? '\nSELFTEST: ALL CHECKS PASSED' : `\nSELFTEST: ${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('SELFTEST ERROR:', err);
  process.exit(1);
});
