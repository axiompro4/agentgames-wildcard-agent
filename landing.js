'use strict';
/**
 * Landing / demo page for the Villaintzy Gatekeeper agent (Wildcard entry).
 *
 * A single self-contained HTML document (inline CSS/JS, no external assets)
 * served at GET / by server.js and by api/agent.js. The page includes a
 * browser-side simulator that re-implements the exact Gatekeeper decision
 * rules of server.js (same field validation, same check order, BigInt
 * integer comparisons) so visitors can run the gate themselves. The
 * production endpoint itself only accepts HMAC-signed tasks from the
 * Agent Games platform — the simulator never talks to it.
 */

const LANDING_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Villaintzy Gatekeeper — ZK Proof Payment Verification</title>
<meta name="description" content="A self-hosted agent that verifies Groth16 proof-backed payment requests against a registered condition. Built for zkVerify Agent Games Season 01.">
<style>
  :root{
    --bg:#0b0f14; --panel:#121a22; --panel2:#0e141b; --line:#22303d;
    --text:#e6edf3; --muted:#93a5b5; --accent:#3ddc97; --accent2:#39c5cf;
    --red:#ff6b6b; --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    line-height:1.55;-webkit-font-smoothing:antialiased}
  a{color:var(--accent2);text-decoration:none}
  a:hover{text-decoration:underline}
  .wrap{max-width:960px;margin:0 auto;padding:0 20px 64px}
  header{display:flex;align-items:center;justify-content:space-between;gap:12px;
    padding:20px 0 8px;flex-wrap:wrap}
  .brand{font-weight:700;font-size:18px;letter-spacing:.2px}
  .brand span{color:var(--accent)}
  .pill{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--line);
    border-radius:999px;padding:5px 12px;font-size:12.5px;color:var(--muted);background:var(--panel2)}
  .dot{width:9px;height:9px;border-radius:50%;background:#8a97a5;display:inline-block}
  .dot.on{background:var(--accent);box-shadow:0 0 8px var(--accent)}
  .dot.off{background:var(--red);box-shadow:0 0 8px var(--red)}
  .hero{padding:28px 0 6px}
  .kicker{color:var(--accent);font-size:13px;font-weight:600;letter-spacing:1.6px;text-transform:uppercase}
  h1{font-size:clamp(28px,5.2vw,44px);line-height:1.12;margin:10px 0 14px}
  .lede{color:var(--muted);font-size:17px;max-width:720px;margin:0}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:28px 0 6px}
  .stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
  .stat b{display:block;font-size:22px;color:var(--text)}
  .stat span{font-size:12.5px;color:var(--muted)}
  section{margin-top:36px}
  h2{font-size:21px;margin:0 0 6px}
  .sub{color:var(--muted);margin:0 0 16px;max-width:720px}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px}
  ol.pipeline{list-style:none;margin:0;padding:0;counter-reset:step}
  ol.pipeline li{display:flex;gap:14px;padding:12px 2px;border-bottom:1px solid var(--line);align-items:baseline}
  ol.pipeline li:last-child{border-bottom:none}
  .num{counter-increment:step;flex:0 0 auto;width:26px;height:26px;border-radius:50%;
    border:1px solid var(--accent);color:var(--accent);font-size:13px;font-weight:700;
    display:inline-flex;align-items:center;justify-content:center;transform:translateY(4px)}
  .num::before{content:counter(step)}
  .check-body{flex:1;min-width:0}
  .check-body b{display:block}
  .check-body p{margin:2px 0 0;color:var(--muted);font-size:14px}
  code,.code{font-family:var(--mono);font-size:.92em;background:#0a0f16;border:1px solid var(--line);
    border-radius:6px;padding:1px 6px;color:#c9f5e0;white-space:nowrap}
  .code-bad{color:#ffc9c9}
  .presets{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}
  button{cursor:pointer;border-radius:9px;border:1px solid var(--line);background:var(--panel2);
    color:var(--text);padding:8px 14px;font-size:14px}
  button:hover{border-color:var(--accent)}
  button.primary{background:var(--accent);border-color:var(--accent);color:#06251a;font-weight:700;font-size:15px;padding:11px 22px}
  button.primary:hover{filter:brightness(1.08)}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px 16px}
  @media (max-width:640px){.grid{grid-template-columns:1fr}}
  label{display:block;font-size:12.5px;color:var(--muted);margin-bottom:5px;font-family:var(--mono)}
  input{width:100%;background:#0a0f16;border:1px solid var(--line);border-radius:8px;color:var(--text);
    padding:9px 10px;font-family:var(--mono);font-size:13px}
  input:focus{outline:none;border-color:var(--accent)}
  .run-row{display:flex;align-items:center;gap:14px;margin-top:18px;flex-wrap:wrap}
  .result{margin-top:18px;border-radius:12px;border:1px solid var(--line);background:var(--panel2);padding:16px 18px;display:none}
  .result.show{display:block}
  .decision{font-size:26px;font-weight:800;letter-spacing:.5px}
  .ok{color:var(--accent)} .bad{color:var(--red)}
  .reason{font-family:var(--mono);font-size:14px;margin-top:2px}
  .explain{color:var(--muted);margin:6px 0 0;font-size:14.5px}
  .note{font-size:13px;color:var(--muted);border-left:3px solid var(--accent);padding:6px 0 6px 12px;margin-top:16px}
  .links{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
  .link-card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
  .link-card b{display:block;margin-bottom:4px}
  .link-card p{margin:0;color:var(--muted);font-size:14px}
  footer{margin-top:44px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font-size:13px}
</style>
</head>
<body>
<div class="wrap">

  <header>
    <div class="brand">Villaintzy <span>Gatekeeper</span></div>
    <div class="pill"><span class="dot" id="statusDot"></span><span id="statusText">CHECKING…</span></div>
  </header>

  <div class="hero">
    <div class="kicker">zkVerify · Agent Games Season 01</div>
    <h1>ZK proof payment verification, decided before value moves.</h1>
    <p class="lede">
      Villaintzy Gatekeeper is a self-hosted agent that verifies Groth16 proof-backed
      payment requests against a registered condition — the verification key, the
      recipient, the threshold, the expiry — and returns a signed APPROVE or REJECT
      verdict inside the platform deadline. It competes in the
      <b>Proof Gatekeeper</b> track of Agent Games Season 01; this page and the
      open-source repository are its <b>Wildcard</b> entry.
    </p>
  </div>

  <div class="stats">
    <div class="stat"><b>9 / 9</b><span>correct live practice decisions (calibration record)</span></div>
    <div class="stat"><b>~260–530 ms</b><span>per decision, measured in practice</span></div>
    <div class="stat"><b>15 s</b><span>platform deadline per task</span></div>
    <div class="stat"><b>6 checks</b><span>must all pass before APPROVE</span></div>
  </div>

  <section>
    <h2>The decision pipeline</h2>
    <p class="sub">Every task arrives as an HMAC-signed envelope. The agent verifies the
      signature (timing-safe), then runs these checks in order — the first failure
      decides, with the platform's own reason code:</p>
    <div class="panel">
      <ol class="pipeline">
        <li><span class="num"></span><div class="check-body">
          <b>Verification key matches the registered key</b>
          <p>The key that produced the proof must be the key registered for the condition.
          Otherwise <span class="code code-bad">REJECT · VK_SUBSTITUTION</span></p></div></li>
        <li><span class="num"></span><div class="check-body">
          <b>Recipient matches the condition recipient</b>
          <p>The transfer must go exactly where the condition says.
          Otherwise <span class="code code-bad">REJECT · RECIPIENT_MISMATCH</span></p></div></li>
        <li><span class="num"></span><div class="check-body">
          <b>Condition not expired</b>
          <p>The current block must not be past the condition's expiry block.
          Otherwise <span class="code code-bad">REJECT · EXPIRED_CONDITION</span></p></div></li>
        <li><span class="num"></span><div class="check-body">
          <b>Amount within the transfer cap</b>
          <p>The amount must not exceed the maximum transfer.
          Otherwise <span class="code code-bad">REJECT · EXCEEDS_MAX_TRANSFER</span></p></div></li>
        <li><span class="num"></span><div class="check-body">
          <b>Public balance meets the minimum</b>
          <p>The proven public balance must reach the required threshold.
          Otherwise <span class="code code-bad">REJECT · THRESHOLD_MISMATCH</span></p></div></li>
        <li><span class="num"></span><div class="check-body">
          <b>Proof reference not reused</b>
          <p>A proof reference that was already approved cannot be spent twice.
          Otherwise <span class="code code-bad">REJECT · PROOF_REUSED</span></p></div></li>
        <li><span class="num"></span><div class="check-body">
          <b>All checks passed</b>
          <p><span class="code">APPROVE · VALID_CONDITION</span> — the signed verdict is
          returned to the platform, typically in well under a second.</p></div></li>
      </ol>
    </div>
  </section>

  <section>
    <h2>Try the gate — browser simulator</h2>
    <p class="sub">These are the live rules, re-implemented in your browser with the same
      field validation, the same check order and BigInt comparisons. Pick a scenario or
      edit the fields, then run the gate.</p>
    <div class="panel">
      <div class="presets">
        <button type="button" data-preset="valid">Valid request</button>
        <button type="button" data-preset="recipient">Wrong recipient</button>
        <button type="button" data-preset="expired">Expired</button>
        <button type="button" data-preset="vk">Key swapped</button>
        <button type="button" data-preset="threshold">Below threshold</button>
      </div>
      <form id="simForm" autocomplete="off">
        <div class="grid">
          <div><label for="f_registered_vk">registered_vk</label><input id="f_registered_vk" spellcheck="false"></div>
          <div><label for="f_proof_vk">proof_vk</label><input id="f_proof_vk" spellcheck="false"></div>
          <div><label for="f_recipient">recipient</label><input id="f_recipient" spellcheck="false"></div>
          <div><label for="f_condition_recipient">condition_recipient</label><input id="f_condition_recipient" spellcheck="false"></div>
          <div><label for="f_public_balance">public_balance</label><input id="f_public_balance" spellcheck="false"></div>
          <div><label for="f_minimum">minimum</label><input id="f_minimum" spellcheck="false"></div>
          <div><label for="f_amount">amount</label><input id="f_amount" spellcheck="false"></div>
          <div><label for="f_max_transfer">max_transfer</label><input id="f_max_transfer" spellcheck="false"></div>
          <div><label for="f_current_block">current_block</label><input id="f_current_block" spellcheck="false"></div>
          <div><label for="f_expiry_block">expiry_block</label><input id="f_expiry_block" spellcheck="false"></div>
          <div><label for="f_proof_tx">proof_tx (reference)</label><input id="f_proof_tx" spellcheck="false"></div>
        </div>
        <div class="run-row">
          <button type="submit" class="primary">Run the gate</button>
          <span style="color:var(--muted);font-size:13.5px">Tip: run the valid request twice — the second run is rejected as a reused proof.</span>
        </div>
      </form>
      <div class="result" id="simResult">
        <div class="decision" id="simDecision"></div>
        <div class="reason" id="simReason"></div>
        <p class="explain" id="simExplain"></p>
      </div>
      <p class="note">Browser simulator of the live rules — the production endpoint only
        accepts HMAC-signed tasks from the Agent Games platform. Reuse detection here is
        kept in this page session, mirroring the server's in-memory seen-set.</p>
    </div>
  </section>

  <section>
    <h2>Endpoints &amp; code</h2>
    <div class="links">
      <div class="link-card"><b>Task endpoint</b>
        <p><span class="code">POST /agent</span> — HMAC-signed tasks only; unsigned or forged
        requests are rejected with HTTP 401.</p></div>
      <div class="link-card"><b>Liveness</b>
        <p><a href="/health"><span class="code">GET /health</span></a> — returns
        <span class="code">{"ok":true}</span>; the status pill above reads it live.</p></div>
      <div class="link-card"><b>Source code</b>
        <p><a href="https://github.com/axiompro4/agentgames-wildcard-agent">github.com/axiompro4/agentgames-wildcard-agent</a> —
        zero-dependency Node, with the full verification record.</p></div>
    </div>
  </section>

  <footer>
    villaintzy-agent · Built for zkVerify Agent Games Season 01 — Proof Gatekeeper track;
    this page and repository are the Wildcard entry. No human is in the loop at decision
    time; the operator keeps account control and the secret, the agent does the work.
  </footer>

</div>
<script>
(function(){
  // --- live status pill -------------------------------------------------
  var dot = document.getElementById('statusDot');
  var txt = document.getElementById('statusText');
  fetch('/health').then(function(r){ return r.json(); }).then(function(j){
    if (j && j.ok === true) { dot.className = 'dot on'; txt.textContent = 'AGENT ONLINE'; }
    else { dot.className = 'dot off'; txt.textContent = 'AGENT UNREACHABLE'; }
  }).catch(function(){ dot.className = 'dot off'; txt.textContent = 'AGENT UNREACHABLE'; });

  // --- simulator: same rules, same order as the production gate ---------
  var VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
  var RCPT = '0xabcdef1234567890abcdef1234567890abcdef12';
  var BASE = {
    registered_vk: VK, proof_vk: VK,
    recipient: RCPT, condition_recipient: RCPT,
    public_balance: '1460', minimum: '1000',
    amount: '500', max_transfer: '1000',
    current_block: '8420000', expiry_block: '8430000',
    proof_tx: '0xb7287d1633ee47d6896c6030a3acf422'
  };
  var PRESETS = {
    valid:     {},
    recipient: { recipient: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
                 proof_tx: '0xb7287d1633ee47d6896c6030a3acf423' },
    expired:   { current_block: '8430001',
                 proof_tx: '0xb7287d1633ee47d6896c6030a3acf424' },
    vk:        { proof_vk: '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                 proof_tx: '0xb7287d1633ee47d6896c6030a3acf425' },
    threshold: { public_balance: '999',
                 proof_tx: '0xb7287d1633ee47d6896c6030a3acf426' }
  };
  var FIELDS = Object.keys(BASE);
  function fill(values){
    FIELDS.forEach(function(k){
      document.getElementById('f_' + k).value = values[k];
    });
  }
  function readForm(){
    var out = {};
    FIELDS.forEach(function(k){ out[k] = document.getElementById('f_' + k).value; });
    return out;
  }
  document.querySelectorAll('[data-preset]').forEach(function(btn){
    btn.addEventListener('click', function(){
      var merged = {}; FIELDS.forEach(function(k){ merged[k] = BASE[k]; });
      var over = PRESETS[btn.getAttribute('data-preset')] || {};
      Object.keys(over).forEach(function(k){ merged[k] = over[k]; });
      fill(merged);
      document.getElementById('simResult').className = 'result';
    });
  });

  function hexField(v){
    if (typeof v !== 'string') return null;
    var s = v.trim();
    return /^0x[0-9a-fA-F]+$/.test(s) ? s.toLowerCase() : null;
  }
  function intField(v){
    if (typeof v !== 'string') return null;
    var s = v.trim();
    return /^-?[0-9]+$/.test(s) ? BigInt(s) : null;
  }
  var seenTx = new Set();
  var EXPLAIN = {
    VALID_CONDITION: 'All checks passed — the proof satisfies the registered condition.',
    VK_SUBSTITUTION: 'The proof was produced under a different verification key than the registered one.',
    RECIPIENT_MISMATCH: 'The transfer recipient differs from the condition recipient.',
    EXPIRED_CONDITION: 'The current block is past the condition expiry block.',
    EXCEEDS_MAX_TRANSFER: 'The amount exceeds the maximum transfer allowed by the condition.',
    THRESHOLD_MISMATCH: 'The proven public balance is below the required minimum.',
    PROOF_REUSED: 'This proof reference was already approved in this session — proofs are single-use.',
    MALFORMED_INPUT: 'A field is missing or malformed (hex fields need a 0x-prefixed hex string; amounts and blocks must be whole numbers).'
  };
  function decide(raw){
    var p = {
      registered_vk: hexField(raw.registered_vk), proof_vk: hexField(raw.proof_vk),
      recipient: hexField(raw.recipient), condition_recipient: hexField(raw.condition_recipient),
      proof_tx: hexField(raw.proof_tx),
      expiry_block: intField(raw.expiry_block), current_block: intField(raw.current_block),
      amount: intField(raw.amount), max_transfer: intField(raw.max_transfer),
      public_balance: intField(raw.public_balance), minimum: intField(raw.minimum)
    };
    var bad = Object.keys(p).some(function(k){ return p[k] === null; });
    if (bad) return { decision: 'REJECT', reason_code: 'MALFORMED_INPUT' };
    if (p.proof_vk !== p.registered_vk) return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
    if (p.recipient !== p.condition_recipient) return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
    if (p.current_block > p.expiry_block) return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
    if (p.amount > p.max_transfer) return { decision: 'REJECT', reason_code: 'EXCEEDS_MAX_TRANSFER' };
    if (p.public_balance < p.minimum) return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
    if (seenTx.has(p.proof_tx)) return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
    seenTx.add(p.proof_tx);
    return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
  }
  document.getElementById('simForm').addEventListener('submit', function(ev){
    ev.preventDefault();
    var r = decide(readForm());
    var box = document.getElementById('simResult');
    var dec = document.getElementById('simDecision');
    dec.textContent = r.decision;
    dec.className = 'decision ' + (r.decision === 'APPROVE' ? 'ok' : 'bad');
    document.getElementById('simReason').textContent = 'reason_code: ' + r.reason_code;
    document.getElementById('simExplain').textContent = EXPLAIN[r.reason_code] || '';
    box.className = 'result show';
  });

  fill(BASE);
})();
</script>
</body>
</html>
`;

module.exports = { LANDING_HTML };
