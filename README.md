# villaintzy-agent — Agent Games (zkVerify), Season 01

A self-hosted AI agent competing in [Agent Games](https://agentgames.zkverify.io)
Season 01 (zkVerify). The agent is registered for the **Proof Gatekeeper**
track; this public repository — code, live endpoint, and verification record —
is also the entry presented to the **Wildcard** track panel.

The agent runs at a public HTTPS endpoint and speaks the Agent Games agent
protocol end to end: the platform dispatches HMAC-signed tasks, the agent
verifies each signature, decides, and returns a signed JSON response inside
the task deadline. No human is in the loop at decision time; the operator
keeps account control and the secret, the agent does the work.

## Live endpoint

| | |
|---|---|
| Base | `https://agentgames-wildcard-agent-murex.vercel.app` |
| Liveness | `GET /health` → `{ "ok": true }` (unsigned) |
| Task handler | `POST /agent` (signed requests only) |

Verified live: `GET /health` returns `{ ok: true }`, and an unsigned
`POST /agent` is rejected with HTTP 401.

## What it does: Proof Gatekeeper

In the Proof Gatekeeper arena the platform sends the agent a Groth16
proof-backed payment request and the agent must **APPROVE** or **REJECT** it.
A task arrives as a signed envelope:

```json
{
  "type": "agent-games.proof-gatekeeper.v1",
  "task_id": "…",
  "mode": "practice | …",
  "issued_at": "…",
  "deadline_at": "…",
  "input": {
    "registered_vk": "0x…", "proof_vk": "0x…",
    "recipient": "0x…", "condition_recipient": "0x…",
    "public_balance": "1460", "minimum": "1000",
    "amount": "500", "max_transfer": "1000",
    "expiry_block": 8430000, "current_block": 8420000,
    "proof_tx": "0x…"
  }
}
```

The handler pipeline:

1. **Verify** the `x-agent-games-signature` header — HMAC-SHA256 of the raw
   request body, compared timing-safe. Forged or unsigned requests get
   HTTP 401; if no secret is configured the service answers HTTP 503
   (secure by default).
2. **Preflight** — the platform's signed connectivity check is answered with
   `{ ok: true, protocolVersion: "v1" }`, as the protocol requires.
3. **Decide** — the `input` fields are validated and normalized (hex fields
   lowercased; integer fields compared as BigInt, so values of any size are
   exact). Checks run in a fixed order; the first failure decides:

   | # | Check | On failure |
   |---|---|---|
   | — | any required field missing or malformed | `REJECT` · `MALFORMED_INPUT` |
   | 1 | proof verification key ≠ the key registered for the condition | `REJECT` · `VK_SUBSTITUTION` |
   | 2 | transfer recipient ≠ the condition's required recipient | `REJECT` · `RECIPIENT_MISMATCH` |
   | 3 | current block is past the condition's expiry block | `REJECT` · `EXPIRED_CONDITION` |
   | 4 | amount exceeds the maximum transfer | `REJECT` · `EXCEEDS_MAX_TRANSFER` |
   | 5 | public balance below the required minimum threshold | `REJECT` · `THRESHOLD_MISMATCH` |
   | 6 | proof reference (`proof_tx`) already submitted before | `REJECT` · `PROOF_REUSED` |
   | ✓ | all checks pass | `APPROVE` · `VALID_CONDITION` |

   The response is the protocol-v1 schema:
   `{ ok: true, protocolVersion: "v1", decision, reason_code, taskId }`.
4. **Sign** the exact response bytes the same way (HMAC-SHA256 hex in the
   `x-agent-games-signature` response header) and return.

Two honest implementation notes:

- The reuse check keeps an in-memory set of seen `proof_tx` values (FIFO,
  capped at 1,000). In the long-lived `server.js` process that is exact;
  on serverless it is best-effort across warm instances — cold starts and
  parallel instances do not share memory.
- Reason codes for the five trap types observed in live practice match the
  platform's own trap vocabulary exactly. `EXCEEDS_MAX_TRANSFER` and
  `PROOF_REUSED` are implemented rules whose trap types have not yet been
  sampled in practice; their codes are our best-pattern guesses, marked as
  such in the code.

### Verification record (live practice, 15 Nov 2026)

The agent was calibrated against the platform's real practice dispatch —
not a mock:

- **9 of 9 practice decisions correct**, spanning the observed trap types
  `RECIPIENT_MISMATCH`, `THRESHOLD_MISMATCH`, `EXPIRED_CONDITION`,
  `VK_SUBSTITUTION`, and the clean case `VALID_CONDITION` (correct APPROVE).
- **Latency ~260–530 ms** per decision, against the 15-second
  `issued_at` → `deadline_at` window carried by the practice tasks.
- Every practice response's proof was marked **VERIFIED** by the platform.

## Other task types

The same endpoint is protocol-conformant beyond Gatekeeper: signed
preflight, a `forecast` handler and a `bounty` handler (both deterministic
placeholders — clean slots where a forecasting model / research pipeline
attaches), and a well-formed signed acknowledgement for unknown task types,
so the platform always sees a live, conformant agent.

## Architecture

- **Zero dependencies** — Node.js ≥ 18 built-ins only (`node:http`,
  `node:crypto`). No `npm install`, no build step.
- **Two runtimes, one logic:**
  - `server.js` — the standalone service (`POST /agent`, `GET /health`;
    also accepts `/api/agent`). 1 MiB request-body cap.
  - `api/agent.js` — the Vercel serverless port of the same logic;
    `vercel.json` rewrites `/agent` → `/api/agent` and sets a 60-second
    function limit. This is what serves the live endpoint above.
- **Files**

  | File | Purpose |
  |---|---|
  | `server.js` | Standalone agent service (signature verification, preflight, Gatekeeper rules, task router) |
  | `api/agent.js` | Serverless variant of the same service |
  | `selftest.js` | Spins up `server.js` with a dummy secret; verifies the signed round-trip, preflight, Gatekeeper cases, forged-signature 401 |
  | `test-vercel.js` | Same checks against `api/agent.js` with mock req/res |
  | `selftest-output.txt`, `vercel-test-output.txt` | Recorded test runs (18/18 and 16/16 checks passing) |
  | `.env.example` | Configuration template (no real values) |
  | `render.yaml` | Alternative always-on host blueprint (Render) |

- **Secret handling** — the platform generates the agent secret and shows
  it **once** at registration. It reaches this service only as the
  environment variable `AGENT_GAMES_HMAC_SECRET`. It is never stored in
  this repository; `.env` is gitignored.

## Run it locally

```sh
export AGENT_GAMES_HMAC_SECRET='<the one-time secret from registration>'
npm start            # = node server.js, listens on PORT (default 8080)
# -> [agent] villaintzy-agent listening on :8080 (POST /agent, GET /health)
```

Register the full handler URL with Agent Games, e.g.
`https://<your-host>/agent`.

Tests (throwaway dummy secrets, no real credentials):

```sh
npm test             # node selftest.js  -> SELFTEST: ALL CHECKS PASSED
node test-vercel.js  #                  -> VERCEL TEST: ALL 16 CHECKS PASSED
```

## Deploy on Vercel

1. On [vercel.com](https://vercel.com): **Add New… → Project** → import this
   repo → **Deploy**. No build command or install step (zero dependencies).
2. Register the agent on Agent Games with the endpoint
   `https://<project>.vercel.app/agent`.
3. Copy the one-time secret from registration into **Project Settings →
   Environment Variables** as `AGENT_GAMES_HMAC_SECRET` and redeploy.
   Until it is set, signed traffic is answered with HTTP 503.

## License

MIT
