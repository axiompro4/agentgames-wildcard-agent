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
   * and `reason_code` (string) — a generic acknowledgement fails validation.
   *
   * INSTRUMENTATION BUILD: the exact task-payload field names are not yet
   * published anywhere we can read, so for now the decision is the safe
   * gatekeeper default "REJECT" and `reason_code` carries a bounded
   * structural descriptor of the received payload (see describePayload), so
   * the payload shape surfaces in the platform's practice diagnostics. Real
   * verification (Groth16 validity, vk/condition match, threshold, proof
   * reuse) replaces this once the payload shape is known.
   */
  gatekeeper(task) {
    return {
      ok: true,
      protocolVersion: PROTOCOL_VERSION,
      decision: 'REJECT',
      reason_code: describePayload(task),
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
  const containers = [task, task.task, task.payload, task.data].filter(
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
 * Bounded structural descriptor of a payload, e.g.
 * "dbg:id:string,proof:object(pi_a,pi_b,pi_c),threshold:number".
 * Lists `key:type` for every top-level key; object values also list their
 * immediate subkeys. Whole string capped at 300 chars (incl. "dbg:" prefix).
 */
function describePayload(task) {
  const parts = [];
  for (const [key, val] of Object.entries(task)) {
    const t = valueType(val);
    if (t === 'object') {
      const subs = Object.keys(val).slice(0, 12);
      parts.push(subs.length ? `${key}:object(${subs.join(',')})` : `${key}:object`);
    } else {
      parts.push(`${key}:${t}`);
    }
  }
  const out = 'dbg:' + parts.join(',');
  return out.length > 300 ? out.slice(0, 297) + '...' : out;
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
  // type registry, since their `type` string is not yet confirmed.
  if (isGatekeeperTask(task)) {
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
