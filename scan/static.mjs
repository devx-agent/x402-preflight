import { checkOption } from "../src/index.js";
import fs from "fs";
const R = JSON.parse(fs.readFileSync("scan/cdp_resources.json"));
const codes = {}, verd = { ok: 0, warn: 0, block: 0 }, examples = {}; let n = 0; const hosts = new Set(), badHosts = {};
for (const r of R) {
  let t; try { t = new URL(r.resource); } catch { continue; }
  hosts.add(t.host);
  for (const [i, o] of (r.accepts || []).entries()) {
    n++; const c = await checkOption(o, i, Number(r.x402Version) || 2, t, false);
    verd[c.verdict]++;
    for (const f of c.findings) { if (f.level === "info") continue; codes[f.code] = (codes[f.code] || 0) + 1; (examples[f.code] ||= []).length < 3 && examples[f.code].push({ resource: r.resource, msg: f.message }); if (f.level === "error") (badHosts[f.code] ||= new Set()).add(t.host); }
  }
}
const res = { resources: R.length, hosts: hosts.size, options: n, verdicts: verd, finding_counts: Object.fromEntries(Object.entries(codes).sort((a, b) => b[1] - a[1])), error_hosts: Object.fromEntries(Object.entries(badHosts).map(([k, v]) => [k, v.size])), examples };
fs.writeFileSync("scan/static_result.json", JSON.stringify(res, null, 1));
console.log(JSON.stringify({ ...res, examples: undefined }, null, 1));
