import { preflight } from "./src/index.js";
const urls = process.argv.slice(2);
for (const u of urls) { const r = await preflight(new URLSearchParams({ url: u })); console.log(JSON.stringify(r.result ? { v: r.result.verdict, s: r.result.summary, ver: r.result.x402_version, opts: (r.result.options||[]).map(o=>[o.verdict,o.network,o.price_usdc,o.findings.map(f=>f.code)]) } : r)); }
