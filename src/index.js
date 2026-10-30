import { keccak_256 } from "@noble/hashes/sha3";
import { base58 } from "@scure/base";

const VERSION = "1.0.1";
const SERVICE = "DevX x402 Preflight";
const PAY_TO = "0xB3cDDccEe6B150c8efFD55B961afc0Ecefe7f247";
const FACILITATOR = "https://facilitator.payai.network";
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PRICE = "3000"; // 0.003 USDC
const enc = new TextEncoder();
const hex = (u) => Array.from(u, (b) => b.toString(16).padStart(2, "0")).join("");
const b64 = (o) => btoa(String.fromCharCode(...enc.encode(JSON.stringify(o))));
const unb64 = (s) => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(s.trim()), (c) => c.charCodeAt(0))));

// Known USDC deployments and their EIP-712 domain (what an EIP-3009 signature must use)
const NETS = {
  "eip155:8453": { name: "Base", v1: "base", usdc: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", domain: ["USD Coin", "2"], rpc: "https://mainnet.base.org" },
  "eip155:84532": { name: "Base Sepolia", v1: "base-sepolia", usdc: "0x036cbd53842c5426634e7929541ec2318f3dcf7e", domain: ["USDC", "2"], testnet: true, rpc: "https://sepolia.base.org" },
  "eip155:1": { name: "Ethereum", v1: "ethereum", usdc: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", domain: ["USD Coin", "2"], rpc: "https://ethereum-rpc.publicnode.com" },
  "eip155:137": { name: "Polygon", v1: "polygon", usdc: "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", domain: ["USD Coin", "2"], rpc: "https://polygon-bor-rpc.publicnode.com" },
  "eip155:80002": { name: "Polygon Amoy", v1: "polygon-amoy", usdc: "0x41e94eb019c0762f9bfcf9fb1e58725bfb0e7582", domain: ["USDC", "2"], testnet: true },
  "eip155:42161": { name: "Arbitrum One", v1: "arbitrum", usdc: "0xaf88d065e77c8cc2239327c5edb3a432268e5831", domain: ["USD Coin", "2"], rpc: "https://arb1.arbitrum.io/rpc" },
  "eip155:10": { name: "OP Mainnet", v1: "optimism", usdc: "0x0b2c639c533813f4aa9d7837caf62653d097ff85", domain: ["USD Coin", "2"], rpc: "https://mainnet.optimism.io" },
  "eip155:43114": { name: "Avalanche C-Chain", v1: "avalanche", usdc: "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e", domain: ["USD Coin", "2"], rpc: "https://api.avax.network/ext/bc/C/rpc" },
  "eip155:43113": { name: "Avalanche Fuji", v1: "avalanche-fuji", usdc: "0x5425890298aed601595a70ab815c96711a31bc65", domain: ["USD Coin", "2"], testnet: true },
  "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": { name: "Solana", v1: "solana", usdc: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", svm: true },
  "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1": { name: "Solana Devnet", v1: "solana-devnet", usdc: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", svm: true, testnet: true },
};
const V1 = Object.fromEntries(Object.entries(NETS).map(([k, v]) => [v.v1, k]));

function toChecksum(a) {
  a = a.toLowerCase().replace(/^0x/, "");
  const h = hex(keccak_256(enc.encode(a)));
  let o = "0x"; for (let i = 0; i < 40; i++) o += parseInt(h[i], 16) >= 8 ? a[i].toUpperCase() : a[i];
  return o;
}
function evmAddr(a) {
  if (typeof a !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(a)) return { ok: false, why: "not a 20-byte 0x address" };
  if (/^0x0{40}$/i.test(a)) return { ok: false, why: "zero address (funds would be burned)" };
  const mixed = a !== a.toLowerCase() && a !== a.toUpperCase().replace("0X", "0x");
  if (mixed && toChecksum(a) !== a) return { ok: false, why: "EIP-55 checksum mismatch (typo or tampering)" };
  return { ok: true, checksummed: toChecksum(a), checksum_present: mixed };
}
function svmAddr(a) {
  try { const d = base58.decode(a); return d.length === 32 ? { ok: true } : { ok: false, why: "not a 32-byte base58 key" }; } catch { return { ok: false, why: "invalid base58" }; }
}
async function rpc(url, method, params) {
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(6000) });
  const j = await r.json(); if (j.error) throw new Error(j.error.message); return j.result;
}
function privateHost(h) {
  return /^(localhost|.*\.local|.*\.internal|0\.0\.0\.0|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|\[?::1\]?|\[?f[cd])/i.test(h);
}

async function checkOption(o, i, ver, target, onchain) {
  const f = []; // findings: [level, code, message]
  const add = (l, c, m) => f.push({ level: l, code: c, message: m });
  const network = o.network in NETS ? o.network : V1[o.network] || o.network;
  const net = NETS[network];
  if (!["exact", "upto"].includes(o.scheme)) add("warn", "scheme_unknown", `scheme "${o.scheme}" is not exact/upto; most clients cannot pay it`);
  if (!net) add("info", "network_not_in_table", `network "${o.network}" is outside this checker's USDC table; asset/domain checks skipped`);
  if (net?.testnet) add("warn", "testnet", `${net.name} is a testnet: payment has no real value, likely a misconfigured production endpoint`);
  if (ver === 2 && !/^[a-z0-9]+:/.test(o.network || "")) add("warn", "v2_network_not_caip2", "x402 v2 expects a CAIP-2 network id (e.g. eip155:8453)");
  const rawAmt = ver === 2 ? (o.amount ?? o.maxAmountRequired) : (o.maxAmountRequired ?? o.amount);
  if (ver === 2 && o.amount === undefined && o.maxAmountRequired !== undefined) add("warn", "v2_amount_field", "v2 uses `amount`; `maxAmountRequired` is the v1 field name");
  let usd = null;
  if (net && (rawAmt === undefined || !/^\d+$/.test(String(rawAmt)))) add("error", "amount_invalid", /^\d*\.\d+$/.test(String(rawAmt)) ? `amount "${rawAmt}" is a decimal; x402 amounts are integer atomic units (USDC 6 decimals), so standard clients reject or misprice it` : `amount "${rawAmt}" is not an integer string in atomic units`);
  const asset = o.asset || "";
  const isUsdc = net && (net.svm ? asset === net.usdc : asset.toLowerCase() === net.usdc);
  if (net && !isUsdc) add("warn", "asset_not_canonical_usdc", `asset ${asset} is not the canonical USDC on ${net.name}; verify the token before signing`);
  if (isUsdc && /^\d+$/.test(String(rawAmt))) {
    usd = Number(rawAmt) / 1e6;
    if (usd === 0) add("warn", "amount_zero", "price is 0");
    else if (usd > 10) add("warn", "amount_very_high", `price is ${usd} USDC for one call`);
    else if (usd > 1) add("warn", "amount_high", `price is ${usd} USDC for one call`);
  }
  if (net && !net.svm) {
    const p = evmAddr(o.payTo);
    if (!p.ok) add("error", "payto_invalid", `payTo: ${p.why}`);
    else if (o.payTo.toLowerCase() === asset.toLowerCase()) add("error", "payto_is_asset", "payTo equals the token contract; funds would be stuck");
    const ad = evmAddr(asset); if (!ad.ok && asset) add("error", "asset_invalid", `asset: ${ad.why}`);
    if (isUsdc) {
      const [n, v] = net.domain; const ex = o.extra || {};
      if (ex.name === "GatewayWalletBatched") add("info", "circle_gateway_batched", "Circle Gateway batched payment: the signature targets the Gateway Wallet domain, not USDC EIP-3009; needs a Gateway-capable client and a Gateway deposit");
      else if (ex.name === undefined || ex.version === undefined) add("warn", "eip712_domain_missing", `extra.name/extra.version missing; clients must guess the EIP-712 domain (expected "${n}"/"${v}")`);
      else if (ex.name !== n || String(ex.version) !== v) add("error", "eip712_domain_mismatch", `extra is "${ex.name}"/"${ex.version}" but USDC on ${net.name} signs with "${n}"/"${v}"; every EIP-3009 signature will fail verification`);
    }
    if (p.ok && onchain && net.rpc) {
      try { const code = await rpc(net.rpc, "eth_getCode", [o.payTo, "latest"]); add("info", code && code !== "0x" ? "payto_contract" : "payto_eoa", code && code !== "0x" ? "payTo is a smart contract (OK if it is a known wallet/splitter)" : "payTo is an EOA"); } catch { add("info", "payto_rpc_unavailable", "could not query payTo code"); }
    }
  } else if (net?.svm) {
    const p = svmAddr(o.payTo || ""); if (!p.ok) add("error", "payto_invalid", `payTo: ${p.why}`);
    if (!o.extra?.feePayer) add("warn", "svm_feepayer_missing", "Solana exact scheme normally needs extra.feePayer");
  }
  const t = Number(o.maxTimeoutSeconds);
  if (!Number.isFinite(t) || t <= 0) add("warn", "timeout_missing", "maxTimeoutSeconds missing or invalid");
  else if (t < 30) add("warn", "timeout_short", `maxTimeoutSeconds=${t} is shorter than typical settlement latency`);
  else if (t > 3600) add("warn", "timeout_long", `maxTimeoutSeconds=${t}: a signed authorization stays usable for over an hour`);
  const res = ver === 1 ? o.resource : null;
  if (res) { try { if (new URL(res).host !== target.host) add("warn", "resource_host_mismatch", `resource host ${new URL(res).host} differs from the requested host ${target.host}`); } catch { add("warn", "resource_invalid", "resource is not a URL"); } }
  const level = f.some((x) => x.level === "error") ? "block" : f.some((x) => x.level === "warn") ? "warn" : "ok";
  return { index: i, verdict: level, scheme: o.scheme, network, network_name: net?.name || null, asset, asset_is_usdc: !!isUsdc, amount_atomic: rawAmt === undefined ? null : String(rawAmt), price_usdc: usd, payTo: o.payTo, findings: f };
}

async function preflight(q) {
  let target;
  try { target = new URL(q.get("url") || ""); } catch { return { error: "url= is required (absolute https URL)", status: 400 }; }
  if (target.protocol !== "https:") return { error: "only https URLs are supported", status: 400 };
  if (privateHost(target.hostname)) return { error: "private/loopback hosts are not allowed", status: 400 };
  const method = (q.get("method") || "GET").toUpperCase();
  if (!["GET", "POST", "HEAD"].includes(method)) return { error: "method must be GET, POST or HEAD", status: 400 };
  const onchain = q.get("onchain") !== "0";
  let r, ms = Date.now();
  try {
    r = await fetch(target.toString(), { method, redirect: "manual", headers: { "user-agent": "devx-x402-preflight/1.0 (+https://x402-preflight.nextill-pos.workers.dev)", accept: "application/json", ...(method === "POST" ? { "content-type": "application/json" } : {}) }, body: method === "POST" ? "{}" : undefined, signal: AbortSignal.timeout(9000) });
  } catch (e) { return { error: "target unreachable: " + String(e.message || e), status: 502 }; }
  ms = Date.now() - ms;
  const out = { url: target.toString(), method, http_status: r.status, latency_ms: ms, checked_at: new Date().toISOString(), checker_version: VERSION };
  if (r.status >= 300 && r.status < 400) { out.verdict = "warn"; out.summary = `redirect to ${r.headers.get("location")}; many x402 clients do not re-pay after redirects`; return { result: out }; }
  if (r.status !== 402) { out.verdict = "not_x402"; out.summary = `endpoint answered ${r.status} without payment, so it is not paywalled for ${method}`; return { result: out }; }
  const hdr = r.headers.get("payment-required") || r.headers.get("x-payment-required");
  let body = null, text = ""; try { text = await r.text(); body = JSON.parse(text); } catch {}
  let pr = null, source = null, parseErr = null;
  if (hdr) { try { pr = unb64(hdr); source = "PAYMENT-REQUIRED header"; } catch (e) { parseErr = "PAYMENT-REQUIRED header is not base64 JSON"; } }
  if (!pr && body && (body.accepts || body.x402Version)) { pr = body; source = "JSON body"; }
  const top = [];
  const hostErr = r.headers.get("x-vercel-error") || (r.headers.get("cf-mitigated") ? "cloudflare_challenge" : null);
  if (!pr && hostErr) { out.verdict = "block"; out.summary = `the 402 comes from the hosting platform (${hostErr}), not from an x402 server: the service is down or suspended`; out.body_preview = text.slice(0, 200); return { result: out }; }
  if (!pr) { out.verdict = "block"; out.summary = parseErr || "402 without a parseable x402 payment requirement (no PAYMENT-REQUIRED header, no accepts[] body)"; out.body_preview = text.slice(0, 300); return { result: out }; }
  const ver = Number(pr.x402Version);
  if (![1, 2].includes(ver)) top.push({ level: "warn", code: "version_unknown", message: `x402Version=${pr.x402Version}` });
  if (ver === 2 && !hdr) top.push({ level: "warn", code: "v2_header_missing", message: "x402 v2 should send the PAYMENT-REQUIRED header; only the body was found" });
  if (ver === 1 && hdr) top.push({ level: "info", code: "v1_with_header", message: "v1 payload delivered in a v2-style header" });
  if (hdr && body?.accepts && pr !== body) {
    if (Number(body.x402Version) !== Number(pr.x402Version)) top.push({ level: "info", code: "dual_version", message: `v${pr.x402Version} header plus v${body.x402Version} body (backward-compatible dual format)` });
    else if (JSON.stringify(body.accepts) !== JSON.stringify(pr.accepts)) top.push({ level: "warn", code: "header_body_differ", message: "header and body list different payment options" });
  }
  if (ver === 2) {
    const rurl = pr.resource?.url; if (rurl) { try { if (new URL(rurl).host !== target.host) top.push({ level: "warn", code: "resource_host_mismatch", message: `resource.url host ${new URL(rurl).host} differs from ${target.host}` }); } catch {} }
    if (!pr.extensions?.bazaar) top.push({ level: "info", code: "no_bazaar", message: "no bazaar extension: discovery indexes cannot list the input/output schema" });
  }
  const acc = Array.isArray(pr.accepts) ? pr.accepts.slice(0, 12) : [];
  if (!acc.length) top.push({ level: "error", code: "accepts_empty", message: "accepts[] is missing or empty: nothing can be paid" });
  const options = await Promise.all(acc.map((o, i) => checkOption(o || {}, i, ver, target, onchain)));
  const payable = options.filter((o) => o.verdict !== "block");
  const best = payable.filter((o) => o.asset_is_usdc && o.price_usdc !== null).sort((a, b) => (a.verdict === "ok" ? 0 : 1) - (b.verdict === "ok" ? 0 : 1) || a.price_usdc - b.price_usdc)[0] || null;
  const topErr = top.some((x) => x.level === "error"), topWarn = top.some((x) => x.level === "warn");
  out.verdict = topErr || !payable.length ? "block" : topWarn || payable.every((o) => o.verdict !== "ok") ? "warn" : "ok";
  Object.assign(out, { x402_version: ver || null, parsed_from: source, error_field: pr.error || null, description: pr.resource?.description || acc[0]?.description || null, findings: top, options, recommended_option: best ? best.index : null });
  out.summary = out.verdict === "ok" ? `payable: ${payable.length}/${options.length} option(s) pass; cheapest USDC ${best ? best.price_usdc + " on " + best.network_name : "n/a"}` :
    out.verdict === "warn" ? `payable with caveats: ${[...top, ...options.flatMap((o) => o.findings)].filter((x) => x.level === "warn").map((x) => x.code).join(", ")}` :
    `do not pay: ${[...top, ...options.flatMap((o) => o.findings)].filter((x) => x.level === "error").map((x) => x.code).join(", ") || "no payable option"}`;
  return { result: out };
}

const ROUTE = "/v1/preflight";
const DESC = "x402 preflight: before your agent signs a payment, fetch a paywalled URL's 402 and lint it. Parses v1 bodies and v2 PAYMENT-REQUIRED headers, then checks each accepts[] option: known network, canonical USDC, EIP-712 domain (extra.name/version) that a signature will verify against, EIP-55 payTo, zero/contract payTo, amount sanity, timeout, testnet, resource-host mismatch. Returns ok/warn/block per option, findings and the recommended option.";
const EXAMPLE = { url: "https://example.com/paid", http_status: 402, verdict: "block", x402_version: 2, options: [{ index: 0, verdict: "block", network: "eip155:8453", price_usdc: 0.01, findings: [{ level: "error", code: "eip712_domain_mismatch", message: "extra is \"USDC\"/\"2\" but USDC on Base signs with \"USD Coin\"/\"2\"; every EIP-3009 signature will fail verification" }] }], recommended_option: null, summary: "do not pay: eip712_domain_mismatch" };
function requirements() { return { scheme: "exact", network: "eip155:8453", amount: PRICE, asset: USDC_BASE, payTo: PAY_TO, maxTimeoutSeconds: 120, extra: { name: "USD Coin", version: "2" } }; }
function paymentRequired(origin, error) {
  return { x402Version: 2, error: error || "PAYMENT-SIGNATURE header is required",
    resource: { url: origin + ROUTE, description: DESC, mimeType: "application/json", serviceName: SERVICE, tags: ["x402", "payments", "security", "agents"] },
    accepts: [requirements()],
    extensions: { bazaar: { info: { input: { type: "http", method: "GET", queryParams: { url: "https://x402.ottoai.services/crypto-news" } }, output: { type: "json", example: EXAMPLE } },
      schema: { $schema: "https://json-schema.org/draft/2020-12/schema", type: "object", properties: { input: { type: "object", properties: { type: { type: "string", const: "http" }, method: { type: "string", enum: ["GET"] }, queryParams: { type: "object", properties: { url: { type: "string" }, method: { type: "string" }, onchain: { type: "string" } }, required: ["url"] } }, required: ["type", "method"], additionalProperties: false }, output: { type: "object", properties: { type: { type: "string" }, example: { type: "object" } }, required: ["type"] } }, required: ["input"] } } } };
}
const H = { "content-type": "application/json", "access-control-allow-origin": "*", "access-control-expose-headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE" };
const J = (o, status = 200, h = {}) => new Response(JSON.stringify(o, null, 2), { status, headers: { ...H, ...h } });
async function facil(op, body) { const r = await fetch(`${FACILITATOR}/${op}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }); try { return await r.json(); } catch { return {}; } }

const TERMS = `DevX x402 Preflight - Terms of Service (v${VERSION}, effective 2026-10-30)
Operator: DevX (madebydevx.com), contact madebydevx@gmail.com.
1. Service. GET ${ROUTE}?url=<https URL>[&method=GET|POST|HEAD][&onchain=0] makes ONE unpaid request to the URL you give, reads its HTTP 402 payment requirement and returns a JSON lint report. It never signs, sends or relays a payment, and never needs your keys.
2. Price. 0.003 USDC per successful call, x402 v2 "exact" on Base (eip155:8453), paid to ${PAY_TO}, settled through ${FACILITATOR}.
3. When you are NOT charged. Settlement happens only after the report is produced. Invalid input (400), a target that cannot be reached or times out (502), or any internal error returns an error and your payment authorization is not settled. A target that answers but is not paywalled is a valid result ("not_x402") and is charged.
4. Recovery. If you were charged but did not receive a report (e.g. connection dropped), email madebydevx@gmail.com with the Base tx hash from the PAYMENT-RESPONSE header within 30 days; verified duplicate or failed-delivery charges are refunded in USDC on Base to the paying address.
5. Advice only. Findings are heuristic checks of public data at the time of the call, not a guarantee that a payment is safe or that a service will deliver. You decide whether to pay.
6. Acceptable use. No targeting of private/loopback hosts (blocked), no use for flooding third-party sites. We may rate-limit abusive callers.
7. Data. We do not store your query or the target response beyond Cloudflare's standard request logs.
8. Changes. Material changes bump the version above; the price in the live 402 is authoritative.`;

function docs(origin) {
  return { openapi: "3.1.0", info: { title: SERVICE, version: VERSION, description: DESC, termsOfService: origin + "/terms", contact: { name: "DevX", email: "madebydevx@gmail.com", url: "https://madebydevx.com" },
    "x-guidance": `Call GET ${ROUTE}?url=<the x402 URL you are about to pay>. If verdict is "block", do not pay; if "warn", read findings; use recommended_option as the accepts[] index to pay. Invalid input is not charged.` },
    servers: [{ url: origin }],
    paths: { [ROUTE]: { get: { operationId: "x402_preflight", summary: "Lint an x402 payment requirement before paying", description: DESC,
      "x-payment-info": { price: { mode: "fixed", currency: "USD", amount: "0.003000" }, protocols: [{ x402: {} }] },
      parameters: [{ name: "url", in: "query", required: true, schema: { type: "string" }, description: "https URL of the paywalled resource" }, { name: "method", in: "query", required: false, schema: { type: "string", enum: ["GET", "POST", "HEAD"] }, description: "HTTP method to probe (default GET)" }, { name: "onchain", in: "query", required: false, schema: { type: "string", enum: ["1", "0"] }, description: "set 0 to skip the payTo eth_getCode lookup" }],
      responses: { "200": { description: "Lint report", content: { "application/json": { example: EXAMPLE } } }, "400": { description: "Invalid input (not charged)" }, "402": { description: "Payment Required" }, "502": { description: "Target unreachable (not charged)" } } } },
      "/v1/sample": { get: { operationId: "sample", summary: "Free sample report on a fixed public x402 endpoint", security: [], responses: { "200": { description: "Lint report" } } } } } };
}

export default {
  async fetch(req) {
    const url = new URL(req.url), origin = url.origin;
    if (req.method === "OPTIONS") return new Response(null, { headers: { ...H, "access-control-allow-headers": "*", "access-control-allow-methods": "GET, HEAD, OPTIONS" } });
    if (url.pathname === "/" || url.pathname === "/index.json") return J({ service: SERVICE, version: VERSION, by: "DevX (madebydevx.com)", endpoint: origin + ROUTE, price_usdc: 0.003, protocol: "x402 v2 exact, USDC on Base", payTo: PAY_TO, facilitator: FACILITATOR, description: DESC, docs: origin + "/openapi.json", terms: origin + "/terms", free_sample: origin + "/v1/sample", example: origin + ROUTE + "?url=" + encodeURIComponent("https://x402.ottoai.services/crypto-news") });
    if (url.pathname === "/terms") return new Response(TERMS, { headers: { "content-type": "text/plain; charset=utf-8", "access-control-allow-origin": "*" } });
    if (url.pathname === "/openapi.json") return J(docs(origin));
    if (url.pathname === "/.well-known/x402") return J({ version: 1, resources: [origin + ROUTE], description: SERVICE });
    if (url.pathname === "/health") return J({ ok: true, version: VERSION });
    if (url.pathname === "/v1/sample") { const o = await preflight(new URLSearchParams({ url: "https://x402.ottoai.services/crypto-news" })); return J(o.result || o, o.result ? 200 : o.status); }
    if (url.pathname !== ROUTE) return J({ error: "not found", see: origin + "/" }, 404);
    if (req.method !== "GET" && req.method !== "HEAD") return J({ error: "use GET" }, 405);
    const pr = paymentRequired(origin);
    const sig = req.headers.get("PAYMENT-SIGNATURE") || req.headers.get("X-PAYMENT");
    if (!sig) return J(pr, 402, { "PAYMENT-REQUIRED": b64(pr) });
    let payload; try { payload = unb64(sig); } catch { return J({ ...pr, error: "malformed PAYMENT-SIGNATURE" }, 400, { "PAYMENT-REQUIRED": b64(pr) }); }
    const reqs = requirements(), acc = payload.accepted || {};
    if (payload.x402Version !== 2 || acc.network !== reqs.network || acc.payTo?.toLowerCase() !== PAY_TO.toLowerCase() || acc.amount !== reqs.amount || acc.asset?.toLowerCase() !== USDC_BASE.toLowerCase())
      return J({ ...pr, error: "payment does not match requirements (x402 v2, exact, eip155:8453 USDC 3000)" }, 402, { "PAYMENT-REQUIRED": b64(pr) });
    const v = await facil("verify", { x402Version: 2, paymentPayload: payload, paymentRequirements: reqs });
    if (!v.isValid) return J({ ...pr, error: "payment invalid: " + (v.invalidReason || "unknown") }, 402, { "PAYMENT-REQUIRED": b64(pr) });
    let out; try { out = await preflight(url.searchParams); } catch (e) { return J({ error: "internal error, you were not charged", detail: String(e.message || e) }, 500); }
    if (out.error) return J({ error: out.error + " (you were not charged)" }, out.status || 400);
    const s = await facil("settle", { x402Version: 2, paymentPayload: payload, paymentRequirements: reqs });
    if (!s.success) return J({ ...pr, error: "settlement failed: " + (s.errorReason || "unknown") }, 402, { "PAYMENT-REQUIRED": b64(pr), "PAYMENT-RESPONSE": b64(s) });
    return J(out.result, 200, { "PAYMENT-RESPONSE": b64(s) });
  },
};
export { preflight, checkOption };
