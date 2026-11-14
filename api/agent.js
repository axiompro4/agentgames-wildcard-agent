'use strict';
/**
 * agentgames-wildcard-agent — Vercel serverless variant of server.js.
 *
 * Deployed as a plain (non-Next) Vercel function. vercel.json rewrites
 * POST /agent -> /api/agent, so the platform-facing handler path stays /agent.
 *
 * Behaviour mirrors server.js exactly:
 *  - POST: read the RAW request body from the stream, verify header
 *    `x-agent-games-signature` = HMAC-SHA256 hex of the raw body keyed with
 *    env AGENT_GAMES_HMAC_SECRET (timing-safe compare; bad signature -> 401).
 *  - Preflight payloads -> { ok: true, protocolVersion: "v1" }.
 *  - Task payloads are routed by `type` through the same handler registry
 *    (forecast / bounty deterministic placeholders; unknown -> signed ack).
 *  - Every response body is signed the same way (HMAC-SHA256 hex of the raw
 *    response body in the `x-agent-games-signature` response header),
 *    content-type application/json.
 *  - Secret unset -> 503 for signed traffic (secure by default, no dev mode).
 *  - GET on this path -> { ok: true } health JSON.
 *
 * Built-ins only (node:crypto). Node >= 18.
 */

const crypto = require('node:crypto');

const PROTOCOL_VERSION = 'v1';
const AGENT_NAME = process.env.AGENT_GAMES_AGENT_NAME || 'villaintzy-agent';
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const MAX_BODY_BYTES = 1024 * 1024; // 1 MiB cap on task payloads
const SIGNATURE_HEADER = 'x-agent-games-signature';

/* ------------------------------------------------------------------ */
/* HMAC helpers (ported from server.js)                                */
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
  if (expected.length !== provided.length) return false;
  return crypto.timingSafeEqual(expected, provided);
}

/* ------------------------------------------------------------------ */
/* Task routing (ported from server.js)                                */
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
        confidence: 0.5,
        rationale: 'placeholder-strategy: deterministic seed; no market model attached yet',
      },
    };
  },

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
/* Proof Gatekeeper detection + payload descriptor (ported)            */
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
/* Proof Gatekeeper decision rules (ported from server.js)             */
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
 *   VK_MISMATCH -> RECIPIENT_MISMATCH -> PROOF_EXPIRED ->
 *   EXCEEDS_MAX_TRANSFER -> THRESHOLD_NOT_MET -> PROOF_REUSED
 * All checks passed -> APPROVE / ALL_CHECKS_PASSED.
 * Missing/malformed fields -> REJECT / MALFORMED_INPUT (checked first).
 */
function gatekeeperDecision(task) {
  const input = parseGatekeeperInput(task);
  if (!input) return { decision: 'REJECT', reason_code: 'MALFORMED_INPUT' };
  if (input.proof_vk !== input.registered_vk) return { decision: 'REJECT', reason_code: 'VK_MISMATCH' };
  if (input.recipient !== input.condition_recipient) return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  if (input.current_block > input.expiry_block) return { decision: 'REJECT', reason_code: 'PROOF_EXPIRED' };
  if (input.amount > input.max_transfer) return { decision: 'REJECT', reason_code: 'EXCEEDS_MAX_TRANSFER' };
  if (input.public_balance < input.minimum) return { decision: 'REJECT', reason_code: 'THRESHOLD_NOT_MET' };
  if (seenProofTx.has(input.proof_tx)) return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
  rememberProofTx(input.proof_tx);
  return { decision: 'APPROVE', reason_code: 'ALL_CHECKS_PASSED' };
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
/* Request/response plumbing                                           */
/* ------------------------------------------------------------------ */

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('payload too large'));
        if (typeof req.destroy === 'function') req.destroy();
        return;
      }
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendJson(res, status, obj, { sign }) {
  const raw = Buffer.from(JSON.stringify(obj), 'utf8');
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.setHeader('content-length', raw.length);
  if (sign && SECRET) {
    res.setHeader(SIGNATURE_HEADER, hmacHex(SECRET, raw));
  }
  res.end(raw);
}

/* ------------------------------------------------------------------ */
/* Vercel function handler                                             */
/* ------------------------------------------------------------------ */

module.exports = async function handler(req, res) {
  if (req.method === 'GET') {
    sendJson(res, 200, { ok: true }, { sign: false });
    return;
  }

  if (req.method !== 'POST') {
    sendJson(res, 405, { ok: false, error: 'method_not_allowed' }, { sign: false });
    return;
  }

  let rawBody;
  try {
    rawBody = await readRawBody(req);
  } catch (err) {
    sendJson(res, 413, { ok: false, error: 'payload_too_large' }, { sign: false });
    return;
  }

  if (!SECRET) {
    sendJson(
      res,
      503,
      { ok: false, error: 'agent secret not configured', agent: AGENT_NAME },
      { sign: false }
    );
    return;
  }

  const providedSig = req.headers ? req.headers[SIGNATURE_HEADER] : undefined;

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
};

// Ask Vercel/Next-style runtimes not to pre-parse the body: the handler must
// see the exact raw bytes to verify the HMAC signature.
module.exports.config = { api: { bodyParser: false } };
