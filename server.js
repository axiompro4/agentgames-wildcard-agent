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
};

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
