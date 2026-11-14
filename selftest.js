'use strict';
/**
 * Local self-test for the Agent Games agent endpoint.
 *
 * Starts server.js with a dummy secret, then:
 *   1. GET  /health                     -> expects { ok: true }
 *   2. POST /agent  signed preflight    -> expects { ok: true, protocolVersion: "v1" }
 *                                          and a VALID response signature
 *   3. POST /agent  signed forecast task-> expects a signed, well-formed result
 *   4. POST /agent  signed Gatekeeper   -> real decision rules (7 cases a-g)
 *   5. POST /agent  bad signature       -> expects HTTP 401
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

    // 1b. landing/demo page at the site root (Wildcard entry)
    const landingRes = await fetch(`${BASE}/`);
    const landingText = await landingRes.text();
    check(
      'GET / -> 200 HTML landing page mentioning Gatekeeper',
      landingRes.status === 200 &&
        (landingRes.headers.get('content-type') || '').includes('text/html') &&
        landingText.includes('Gatekeeper'),
      `got ${landingRes.status} ${(landingRes.headers.get('content-type') || '')}`
    );

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

    // 4. signed Gatekeeper tasks — real decision rules.
    // GK_INPUT mirrors the platform's real practice payload with the
    // recipient fixed (clean); each case varies one field. proof_tx values
    // are unique per case (except the deliberate reuse case) so the
    // seen-set only fires where intended.
    const GK_INPUT = {
      registered_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: '0xabcdef1234567890abcdef1234567890abcdef12',
      condition_recipient: '0xabcdef1234567890abcdef1234567890abcdef12',
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0x00000000000000000000000000000000',
      proof_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
    };
    const gkTx = (n) => `0x${String(n).padStart(32, '0')}`;
    const gkPayload = (input, taskId) => ({
      type: 'agent-games.proof-gatekeeper.v1',
      task_id: taskId,
      mode: 'practice',
      issued_at: '2026-11-14T20:44:01.961Z',
      deadline_at: '2026-11-14T20:44:16.961Z',
      input,
    });
    const gkCase = async (name, payload, decision, reason) => {
      const r = await postSigned(payload, SECRET);
      check(
        `gatekeeper ${name} -> ${decision}/${reason}`,
        r.status === 200 &&
          r.json?.decision === decision &&
          r.json?.reason_code === reason &&
          /^[A-Z0-9_-]{2,80}$/.test(r.json?.reason_code ?? ''),
        JSON.stringify(r.json)
      );
      return r;
    };

    // (a) the real practice payload, verbatim -> RECIPIENT_MISMATCH
    await gkCase(
      'real practice payload',
      gkPayload(
        {
          registered_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
          minimum: '1000',
          public_balance: '1460',
          expiry_block: 8430000,
          current_block: 8420000,
          recipient: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
          condition_recipient: '0xabcdef1234567890abcdef1234567890abcdef12',
          amount: '500',
          max_transfer: '1000',
          proof_tx: '0xb7287d1633ee47d6896c6030a3acf422',
          proof_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
        },
        'practice_b7287d16-33ee-47d6-896c-6030a3acf422'
      ),
      'REJECT',
      'RECIPIENT_MISMATCH'
    );

    // (b) clean payload -> APPROVE (response signature also verified)
    const clean = await gkCase(
      'clean payload',
      gkPayload({ ...GK_INPUT, proof_tx: gkTx(2) }, 'practice_clean'),
      'APPROVE',
      'VALID_CONDITION'
    );
    check(
      'gatekeeper clean response signature valid',
      verifyResponseSignature(SECRET, clean.rawRes, clean.sigHeader)
    );

    // (c) verification key mismatch
    await gkCase(
      'vk mismatch',
      gkPayload({ ...GK_INPUT, proof_tx: gkTx(3), proof_vk: `0x${'f'.repeat(64)}` }, 'practice_vk'),
      'REJECT',
      'VK_SUBSTITUTION'
    );

    // (d) proof expired (current block past expiry)
    await gkCase(
      'expired',
      gkPayload({ ...GK_INPUT, proof_tx: gkTx(4), current_block: 8430001 }, 'practice_expired'),
      'REJECT',
      'EXPIRED_CONDITION'
    );

    // (e) amount above the transfer cap
    await gkCase(
      'amount above max',
      gkPayload({ ...GK_INPUT, proof_tx: gkTx(5), amount: '1500' }, 'practice_amount'),
      'REJECT',
      'EXCEEDS_MAX_TRANSFER'
    );

    // (f) public balance below the minimum
    await gkCase(
      'balance below minimum',
      gkPayload({ ...GK_INPUT, proof_tx: gkTx(6), public_balance: '999' }, 'practice_balance'),
      'REJECT',
      'THRESHOLD_MISMATCH'
    );

    // (g) same proof_tx submitted twice: first APPROVE, then PROOF_REUSED
    const reusePayload = gkPayload({ ...GK_INPUT, proof_tx: gkTx(7) }, 'practice_reuse');
    await gkCase('reuse first submission', reusePayload, 'APPROVE', 'VALID_CONDITION');
    await gkCase('reuse second submission', reusePayload, 'REJECT', 'PROOF_REUSED');

    // 5. bad signature rejected
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
