import { preflight } from "../src/index.js";
import fs from "fs";
const R = JSON.parse(fs.readFileSync("scan/cdp_resources.json"));
const seen = new Set(), list = [];
for (const r of R) { let u; try { u = new URL(r.resource); } catch { continue; } if (u.protocol !== "https:" || seen.has(u.host)) continue; const m = r.extensions?.bazaar?.info?.input?.method || r.accepts?.[0]?.extra?.method || "GET"; if (String(m).toUpperCase() !== "GET") continue; seen.add(u.host); list.push(r.resource); }
const out = []; let i = 0;
async function worker() { while (i < list.length) { const u = list[i++]; try { const r = await preflight(new URLSearchParams({ url: u, onchain: "0" })); out.push(r.result ? { url: u, verdict: r.result.verdict, status: r.result.http_status, summary: r.result.summary, codes: [...(r.result.findings || []), ...(r.result.options || []).flatMap((o) => o.findings)].filter((f) => f.level !== "info").map((f) => f.code) } : { url: u, verdict: "unreachable", err: r.error }); } catch (e) { out.push({ url: u, verdict: "unreachable", err: String(e) }); } } }
await Promise.all(Array.from({ length: 12 }, worker));
fs.writeFileSync("scan/live_result.json", JSON.stringify(out, null, 1));
const c = {}; for (const o of out) c[o.verdict] = (c[o.verdict] || 0) + 1;
const codes = {}; for (const o of out) for (const k of new Set(o.codes || [])) codes[k] = (codes[k] || 0) + 1;
console.log(list.length, JSON.stringify(c), JSON.stringify(codes));
