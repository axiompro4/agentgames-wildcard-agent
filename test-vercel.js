'use strict';
/**
 * Local test for the Vercel function handler (api/agent.js).
 *
 * Invokes the handler directly with mock req (Readable stream) / res objects
 * and a dummy secret. Checks:
 *  1. Signed preflight -> 200, exact {ok:true, protocolVersion:"v1"} body,
 *     and an `x-agent-games-signature` response header that verifies.
 *  2. Forged signature -> 401.
 *  3. Signed Gatekeeper task -> decision + reason_code (dbg:) per protocol-v1.
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

  // --- 3. Signed Gatekeeper task ---------------------------------------------
  const gkRaw = JSON.stringify({
    type: 'proof_gatekeeper',
    id: 'practice_mock_1',
    proof: {
      pi_a: ['1', '2'],
      pi_b: [['1', '2'], ['3', '4']],
      pi_c: ['1', '2'],
      protocol: 'groth16',
      curve: 'bn128',
    },
    verificationKey: { protocol: 'groth16', curve: 'bn128' },
    publicSignals: ['12345'],
    threshold: 100,
    reference: 'ref-abc',
    condition: 'payment-release',
  });
  const res3 = mockRes();
  await handler(mockReq(gkRaw, { [SIG]: sign(gkRaw), 'content-type': 'application/json' }), res3);
  const gk = res3.body ? JSON.parse(res3.body.toString('utf8')) : null;

  check('gatekeeper: status 200', res3.statusCode === 200);
  check(
    'gatekeeper: decision=REJECT and string reason_code',
    gk && gk.decision === 'REJECT' && typeof gk.reason_code === 'string'
  );
  check(
    'gatekeeper: reason_code dbg lists mock keys',
    !!gk &&
      gk.reason_code.startsWith('dbg:') &&
      gk.reason_code.includes('proof:object(pi_a,pi_b,pi_c,protocol,curve)') &&
      gk.reason_code.includes('verificationKey:object') &&
      gk.reason_code.includes('publicSignals:array') &&
      gk.reason_code.includes('threshold:number') &&
      gk.reason_code.includes('reference:string') &&
      gk.reason_code.includes('condition:string')
  );
  check(
    'gatekeeper: reason_code within 300 chars',
    !!gk && gk.reason_code.length <= 300
  );
  check(
    'gatekeeper: response signature verifies over raw body',
    res3.getHeader(SIG) === sign(res3.body)
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
