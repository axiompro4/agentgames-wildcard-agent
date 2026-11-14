'use strict';
/**
 * Local test for the Vercel function handler (api/agent.js).
 *
 * Invokes the handler directly with mock req (Readable stream) / res objects
 * and a dummy secret. Checks:
 *  1. Signed preflight -> 200, exact {ok:true, protocolVersion:"v1"} body,
 *     and an `x-agent-games-signature` response header that verifies.
 *  2. Forged signature -> 401.
 *  3. Signed Gatekeeper tasks -> real decision rules (7 cases a-g).
 *  4. GET / -> landing page HTML; GET /api/agent -> health JSON (unchanged).
 *
 * Run: node test-vercel.js
 */

process.env.AGENT_GAMES_HMAC_SECRET = 'test-dummy-secret-for-vercel-handler';

const { Readable } = require('node:stream');
const crypto = require('node:crypto');
const handler = require('./api/agent.js');

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
const SIG = 'x-agent-games-signature';

function sign(raw) {
  return crypto.createHmac('sha256', SECRET).update(raw).digest('hex');
}

function mockReq(rawBody, headers) {
  const req = Readable.from([Buffer.from(rawBody, 'utf8')]);
  req.method = 'POST';
  req.headers = headers;
  return req;
}

function mockRes() {
  return {
    statusCode: 200,
    headers: {},
    body: null,
    setHeader(name, value) {
      this.headers[String(name).toLowerCase()] = value;
    },
    getHeader(name) {
      return this.headers[String(name).toLowerCase()];
    },
    end(chunk) {
      this.body = chunk ? Buffer.from(chunk) : Buffer.alloc(0);
      this.finished = true;
    },
  };
}

const results = [];
function check(name, cond) {
  results.push([name, !!cond]);
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}`);
}

(async () => {
  // --- 1. Signed preflight -------------------------------------------------
  const preflightRaw = JSON.stringify({ type: 'preflight' });
  const res1 = mockRes();
  await handler(mockReq(preflightRaw, { [SIG]: sign(preflightRaw), 'content-type': 'application/json' }), res1);

  check('preflight: status 200', res1.statusCode === 200);
  check(
    'preflight: exact v1 contract body',
    res1.body && res1.body.toString('utf8') === '{"ok":true,"protocolVersion":"v1"}'
  );
  const respSig = res1.getHeader(SIG);
  check('preflight: response signature header present', typeof respSig === 'string' && /^[0-9a-f]{64}$/.test(respSig));
  check(
    'preflight: response signature verifies over raw body',
    respSig === sign(res1.body)
  );
  check(
    'preflight: content-type is application/json',
    String(res1.getHeader('content-type')).includes('application/json')
  );

  // --- 2. Forged signature ---------------------------------------------------
  const res2 = mockRes();
  await handler(
    mockReq(preflightRaw, { [SIG]: 'f'.repeat(64), 'content-type': 'application/json' }),
    res2
  );
  check('forged signature: status 401', res2.statusCode === 401);
  check(
    'forged signature: error body',
    res2.body && JSON.parse(res2.body.toString('utf8')).error === 'invalid_signature'
  );

  // --- 3. Signed Gatekeeper tasks — real decision rules ----------------------
  async function callTask(obj) {
    const raw = JSON.stringify(obj);
    const res = mockRes();
    await handler(mockReq(raw, { [SIG]: sign(raw), 'content-type': 'application/json' }), res);
    return {
      status: res.statusCode,
      json: res.body ? JSON.parse(res.body.toString('utf8')) : null,
      sigOk: res.getHeader(SIG) === sign(res.body),
    };
  }
  // GK_INPUT mirrors the platform's real practice payload with the
  // recipient fixed (clean); each case varies one field. proof_tx values
  // are unique per case (except the deliberate reuse case) so the seen-set
  // only fires where intended.
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
  async function gkCase(name, payload, decision, reason) {
    const r = await callTask(payload);
    check(
      `gatekeeper ${name} -> ${decision}/${reason}`,
      r.status === 200 &&
        r.json?.decision === decision &&
        r.json?.reason_code === reason &&
        /^[A-Z0-9_-]{2,80}$/.test(r.json?.reason_code ?? '')
    );
    return r;
  }

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
  check('gatekeeper: clean response signature verifies over raw body', clean.sigOk);

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

  // --- 4. GET routes ---------------------------------------------------------
  function mockGetReq(url) {
    const req = Readable.from([]);
    req.method = 'GET';
    req.headers = {};
    req.url = url;
    return req;
  }
  const resRoot = mockRes();
  await handler(mockGetReq('/'), resRoot);
  check(
    'GET /: landing page HTML mentioning Gatekeeper',
    resRoot.statusCode === 200 &&
      String(resRoot.getHeader('content-type')).includes('text/html') &&
      resRoot.body.toString('utf8').includes('Gatekeeper')
  );
  const resAgentGet = mockRes();
  await handler(mockGetReq('/api/agent'), resAgentGet);
  check(
    'GET /api/agent: health JSON unchanged',
    resAgentGet.statusCode === 200 && resAgentGet.body.toString('utf8') === '{"ok":true}'
  );

  const failed = results.filter(([, ok]) => !ok);
  console.log(
    failed.length === 0
      ? `VERCEL TEST: ALL ${results.length} CHECKS PASSED`
      : `VERCEL TEST: ${failed.length}/${results.length} CHECKS FAILED`
  );
  process.exit(failed.length === 0 ? 0 : 1);
})().catch((err) => {
  console.error('VERCEL TEST: ERROR', err);
  process.exit(1);
});
