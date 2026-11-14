'use strict';
/**
 * agentgames-wildcard-agent
 *
 * Self-hosted agent endpoint for Agent Games (zkVerify) — Season 01, Wildcard track.
 *
 * Protocol (per the Agent Games Build/docs pages):
 *  - The platform POSTs signed tasks to this handler.
 *  - Request header `x-agent-games-signature` = HMAC-SHA256 hex of the RAW request
 *    body, keyed with the agent secret (env AGENT_GAMES_HMAC_SECRET, shown once
 *    by the platform at agent registration time).
 *  - Responses must be signed the same way: HMAC-SHA256 hex of the RAW response
 *    body, returned in the same `x-agent-games-signature` header.
 *  - A signed preflight request must return JSON { ok: true, protocolVersion: "v1" }.
 *
 * Built-ins only (node:http, node:crypto). Node >= 18.
 */

const http = require('node:http');
const crypto = require('node:crypto');

const PROTOCOL_VERSION = 'v1';
const AGENT_NAME = process.env.AGENT_GAMES_AGENT_NAME || 'villaintzy-agent';
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
// DEV mode: only relevant when no secret is configured. When AGENT_GAMES_DEV_MODE=1
// and no secret is set, the handler answers preflight-shaped pings unsigned so the
// wiring can be smoke-tested before the real secret exists. NEVER enable in production.
const DEV_MODE = process.env.AGENT_GAMES_DEV_MODE === '1';
const PORT = Number(process.env.PORT || 8080);
const MAX_BODY_BYTES = 1024 * 1024; // 1 MiB cap on task payloads
const SIGNATURE_HEADER = 'x-agent-games-signature';

if (!SECRET) {
  console.warn(
    '[agent] WARNING: AGENT_GAMES_HMAC_SECRET is not set. ' +
      (DEV_MODE
        ? 'DEV mode is ON: preflight pings will be answered UNSIGNED. Do not use this in production.'
        : 'Signed requests cannot be verified or answered. Set the secret (or AGENT_GAMES_DEV_MODE=1 for a local smoke test).')
  );
}

/* ------------------------------------------------------------------ */
/* HMAC helpers                                                        */
/* ------------------------------------------------------------------ */

function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function signatureMatches(secret, rawBody, providedHex) {
  if (typeof providedHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(providedHex.trim())) {
    return false;
  }
  const expected = Buffer.from(hmacHex(secret, rawBody), 'utf8');
  const provided = Buffer.from(providedHex.trim().toLowerCase(), 'utf8');
  // timingSafeEqual throws on length mismatch; lengths are pinned by the regex above,
  // but double-check anyway.
  if (expected.length !== provided.length) return false;
  return crypto.timingSafeEqual(expected, provided);
}

/* ------------------------------------------------------------------ */
/* Task routing — drop real strategy logic into these handlers.        */
/* Each handler receives the parsed task object and returns a plain    */
/* object that becomes the (signed) JSON response body.                */
/* ------------------------------------------------------------------ */

/** Deterministic 32-bit hash of a string — placeholder "strategy" seed. */
function stableHash(str) {
  let h = 2166136261; // FNV-1a offset basis
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

const taskHandlers = {
  /**
   * Forecast / prediction tasks.
   * PLACEHOLDER strategy: derive a deterministic pseudo-view from the task id
   * so responses are reproducible. Replace with a real forecasting model
   * (market data + calibration) before relying on it competitively.
   */
  forecast(task) {
    const seed = stableHash(String(task.id ?? task.question ?? 'forecast'));
    const answer = seed % 2 === 0 ? 'yes' : 'no';
    return {
      ok: true,
      protocolVersion: PROTOCOL_VERSION,
      type: 'forecast',
      taskId: task.id ?? null,
      result: {
        answer,
        // Placeholder confidence — deliberately mid-range until a real model lands.
        confidence: 0.5,
        rationale: 'placeholder-strategy: deterministic seed; no market model attached yet',
      },
    };
  },

  /**
   * Bounty-hunting / research tasks.
   * PLACEHOLDER: acknowledge with a structured work plan. A real implementation
   * would run the research pipeline and fill in `findings`.
   */
  bounty(task) {
    return {
      ok: true,
      protocolVersion: PROTOCOL_VERSION,
      type: 'bounty',
      taskId: task.id ?? null,
      result: {
        status: 'acknowledged',
        plan: ['parse brief', 'gather sources', 'verify claims', 'compile submission'],
        findings: [],
        rationale: 'placeholder-strategy: acknowledgement only; research pipeline not attached yet',
      },
    };
  },

  /**
   * Proof Gatekeeper tasks (protocol-v1).
   *
   * The platform's schema requires top-level `decision` ("APPROVE"|"REJECT")
   * and `reason_code` matching /^[A-Z0-9_-]{2,80}$/ — a generic
   * acknowledgement fails validation.
   *
   * REAL decision rules (see gatekeeperDecision): the task carries an
   * `input` object describing a proof-backed transfer; the agent approves
   * only if the proof's verification key matches the registered key, the
   * recipient matches the condition, the proof is unexpired, the amount is
   * within the transfer cap, the public balance meets the minimum, and the
   * proof has not been seen before.
   */
  gatekeeper(task) {
    const { decision, reason_code } = gatekeeperDecision(task);
    return {
      ok: true,
      protocolVersion: PROTOCOL_VERSION,
      decision,
      reason_code,
      taskId: task.id ?? task.taskId ?? task.task_id ?? null,
    };
  },
};

/* ------------------------------------------------------------------ */
/* Proof Gatekeeper detection + payload descriptor                     */
/* ------------------------------------------------------------------ */

const GATEKEEPER_TYPE_WORDS = ['gatekeeper', 'gate_keeper', 'gate-keeper', 'proof'];
const PROOF_FIELD_NAMES = [
  'proof', 'proofdata', 'proof_data',
  'verificationkey', 'verification_key', 'vk', 'vkhash', 'vk_hash',
  'publicsignals', 'publicinputs', 'public_signals', 'public_inputs',
  'threshold', 'minthreshold', 'min_threshold',
  'reference', 'ref', 'proofreference', 'proof_reference',
  'condition', 'conditionid', 'condition_id',
  // Field names of the confirmed Gatekeeper `input` object.
  'registered_vk', 'proof_vk', 'proof_tx', 'condition_recipient', 'public_balance',
];

/**
 * Liberal Gatekeeper detection: a type/kind/event/category/game/track/action
 * field mentioning gatekeeper/proof, or any proof-ish field on the task (or a
 * nested task/payload/data object).
 */
function isGatekeeperTask(task) {
  if (!task || typeof task !== 'object') return false;
  const hints = [task.type, task.kind, task.event, task.category, task.game, task.track, task.action]
    .filter((v) => typeof v === 'string')
    .join(' ')
    .toLowerCase();
  if (GATEKEEPER_TYPE_WORDS.some((w) => hints.includes(w))) return true;
  const containers = [task, task.task, task.payload, task.data, task.input].filter(
    (o) => o && typeof o === 'object' && !Array.isArray(o)
  );
  for (const c of containers) {
    if (c !== task) {
      const inner = String(c.type ?? c.kind ?? '').toLowerCase();
      if (GATEKEEPER_TYPE_WORDS.some((w) => inner.includes(w))) return true;
    }
    const keys = new Set(Object.keys(c).map((k) => k.toLowerCase()));
    if (PROOF_FIELD_NAMES.some((f) => keys.has(f))) return true;
  }
  return false;
}

function valueType(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v; // string | number | boolean | object | undefined
}

/**
 * Full structural descriptor of a payload, e.g.
 * "id:string,proof:object(pi_a,pi_b,pi_c),threshold:number".
 * Lists `key:type` for every top-level key; object values also list ALL
 * their immediate subkeys. Structure only — never any scalar values.
 * Used for the GK_STRUCTURE log line (Vercel Logs backup channel).
 */
function describeStructure(task) {
  const parts = [];
  for (const [key, val] of Object.entries(task)) {
    const t = valueType(val);
    if (t === 'object') {
      const subs = Object.keys(val);
      parts.push(subs.length ? `${key}:object(${subs.join(',')})` : `${key}:object`);
    } else {
      parts.push(`${key}:${t}`);
    }
  }
  return parts.join(',');
}

/* ------------------------------------------------------------------ */
/* Proof Gatekeeper decision rules                                     */
/* ------------------------------------------------------------------ */

/**
 * Seen proof_tx values, for the reuse rule. NOTE (serverless limitation):
 * this set lives in process memory only — on Vercel it is best-effort
 * across warm instances of api/agent.js; cold starts and parallel
 * instances do not share it, so reuse detection there is advisory, not
 * guaranteed. (server.js as a long-lived process keeps it reliably.)
 */
const SEEN_PROOF_TX_LIMIT = 1000;
const seenProofTx = new Set();

function rememberProofTx(tx) {
  seenProofTx.add(tx);
  // FIFO eviction: Sets iterate in insertion order, so the first value is
  // the oldest.
  while (seenProofTx.size > SEEN_PROOF_TX_LIMIT) {
    seenProofTx.delete(seenProofTx.values().next().value);
  }
}

/** Hex string field (address / hash): returns the lowercased value or null. */
function hexField(v) {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  return /^0x[0-9a-fA-F]+$/.test(s) ? s.toLowerCase() : null;
}

/** Integer field (string or number) -> BigInt, or null when malformed. */
function intField(v) {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number') return Number.isInteger(v) ? BigInt(v) : null;
  if (typeof v === 'string') {
    const s = v.trim();
    return /^-?\d+$/.test(s) ? BigInt(s) : null;
  }
  return null;
}

/**
 * Extract and validate the Gatekeeper rule fields from a task. Fields live
 * on `task.input`; when that is absent they are looked up on the task
 * itself. Returns normalized values (lowercased hex strings, BigInt
 * integers), or null when any required field is missing/malformed.
 */
function parseGatekeeperInput(task) {
  const raw =
    task && typeof task === 'object' && task.input && typeof task.input === 'object' && !Array.isArray(task.input)
      ? task.input
      : task ?? {};
  const parsed = {
    registered_vk: hexField(raw.registered_vk),
    proof_vk: hexField(raw.proof_vk),
    recipient: hexField(raw.recipient),
    condition_recipient: hexField(raw.condition_recipient),
    proof_tx: hexField(raw.proof_tx),
    expiry_block: intField(raw.expiry_block),
    current_block: intField(raw.current_block),
    amount: intField(raw.amount),
    max_transfer: intField(raw.max_transfer),
    public_balance: intField(raw.public_balance),
    minimum: intField(raw.minimum),
  };
  return Object.values(parsed).includes(null) ? null : parsed;
}

/**
 * Gatekeeper decision. First failure wins, in this order:
 *   VK_SUBSTITUTION -> RECIPIENT_MISMATCH -> EXPIRED_CONDITION ->
 *   EXCEEDS_MAX_TRANSFER -> THRESHOLD_MISMATCH -> PROOF_REUSED
 * All checks passed -> APPROVE / VALID_CONDITION.
 * Missing/malformed fields -> REJECT / MALFORMED_INPUT (checked first).
 * Note: EXCEEDS_MAX_TRANSFER and PROOF_REUSED are unconfirmed guesses —
 * those trap types have not been sampled in live practice yet; the other
 * codes match the platform's observed trap-type vocabulary exactly.
 */
function gatekeeperDecision(task) {
  const input = parseGatekeeperInput(task);
  if (!input) return { decision: 'REJECT', reason_code: 'MALFORMED_INPUT' };
  if (input.proof_vk !== input.registered_vk) return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  if (input.recipient !== input.condition_recipient) return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  if (input.current_block > input.expiry_block) return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  if (input.amount > input.max_transfer) return { decision: 'REJECT', reason_code: 'EXCEEDS_MAX_TRANSFER' };
  if (input.public_balance < input.minimum) return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  if (seenProofTx.has(input.proof_tx)) return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
  rememberProofTx(input.proof_tx);
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

/** Preflight detection: explicit markers the platform's connectivity check may use. */
function isPreflight(task) {
  if (!task || typeof task !== 'object') return false;
  if (task.preflight === true) return true;
  const t = String(task.type ?? task.kind ?? task.action ?? '').toLowerCase();
  return t === 'preflight' || t === 'ping' || t === 'health' || t === 'handshake' || t === 'verify';
}

/** Route a parsed task payload to a handler and produce the response body object. */
function handleTask(task) {
  if (isPreflight(task) || Object.keys(task).length === 0) {
    return { status: 200, body: { ok: true, protocolVersion: PROTOCOL_VERSION } };
  }
  // Proof Gatekeeper tasks have their own protocol-v1 response schema
  // (decision + reason_code) and are detected liberally — before the generic
  // type registry. Confirmed `type`: "agent-games.proof-gatekeeper.v1".
  if (isGatekeeperTask(task)) {
    // Diagnostic channel: full payload structure (keys + types + immediate
    // subkeys, never scalar values) lands in the server logs.
    console.log('GK_STRUCTURE ' + describeStructure(task));
    return { status: 200, body: taskHandlers.gatekeeper(task) };
  }
  const type = String(task.type ?? task.taskType ?? task.task?.type ?? '').toLowerCase();
  const handler = taskHandlers[type];
  if (handler) {
    return { status: 200, body: handler(task) };
  }
  // Unknown task type: well-formed acknowledgement so the platform sees a live,
  // protocol-conformant agent rather than an error.
  return {
    status: 200,
    body: {
      ok: true,
      protocolVersion: PROTOCOL_VERSION,
      type: 'acknowledgement',
      taskId: task.id ?? null,
      receivedType: type || null,
      result: { status: 'received', note: 'no specialised handler for this task type yet' },
    },
  };
}

/* ------------------------------------------------------------------ */
/* HTTP plumbing                                                       */
/* ------------------------------------------------------------------ */

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('payload too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/**
 * Send a JSON response. When a secret is configured (or the payload is a
 * preflight in signed mode), the exact response bytes are signed and the
 * signature is attached in the platform's header convention.
 */
function sendJson(res, status, obj, { sign }) {
  const raw = Buffer.from(JSON.stringify(obj), 'utf8');
  const headers = { 'content-type': 'application/json', 'content-length': raw.length };
  if (sign && SECRET) {
    headers[SIGNATURE_HEADER] = hmacHex(SECRET, raw);
  }
  res.writeHead(status, headers);
  res.end(raw);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');

  if (req.method === 'GET' && url.pathname === '/health') {
    sendJson(res, 200, { ok: true }, { sign: false });
    return;
  }

  if (req.method === 'POST' && (url.pathname === '/agent' || url.pathname === '/agent/' || url.pathname === '/api/agent' || url.pathname === '/api/agent/')) {
    let rawBody;
    try {
      rawBody = await readRawBody(req);
    } catch (err) {
      sendJson(res, 413, { ok: false, error: 'payload_too_large' }, { sign: false });
      return;
    }

    const providedSig = req.headers[SIGNATURE_HEADER];

    if (!SECRET) {
      // No secret configured: only DEV-mode preflight-shaped pings are answered,
      // unsigned, so the endpoint wiring can be smoke-tested pre-registration.
      let parsed = null;
      try { parsed = JSON.parse(rawBody.toString('utf8') || '{}'); } catch { /* ignore */ }
      if (DEV_MODE && isPreflight(parsed ?? {})) {
        console.warn('[agent] DEV mode: answering unsigned preflight ping.');
        sendJson(res, 200, { ok: true, protocolVersion: PROTOCOL_VERSION }, { sign: false });
        return;
      }
      sendJson(
        res,
        503,
        { ok: false, error: 'agent secret not configured', agent: AGENT_NAME },
        { sign: false }
      );
      return;
    }

    if (!signatureMatches(SECRET, rawBody, providedSig)) {
      sendJson(res, 401, { ok: false, error: 'invalid_signature' }, { sign: false });
      return;
    }

    let task;
    try {
      task = JSON.parse(rawBody.toString('utf8') || '{}');
    } catch {
      sendJson(res, 400, { ok: false, error: 'invalid_json' }, { sign: true });
      return;
    }

    const { status, body } = handleTask(task);
    sendJson(res, status, body, { sign: true });
    return;
  }

  sendJson(res, 404, { ok: false, error: 'not_found' }, { sign: false });
});

server.listen(PORT, () => {
  console.log(`[agent] ${AGENT_NAME} listening on :${PORT} (POST /agent, GET /health)`);
});
