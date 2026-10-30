# x402 Preflight

Lint an x402 payment requirement **before** your agent signs it.

Live API: `GET https://x402-preflight.nextill-pos.workers.dev/v1/preflight?url=<paywalled https URL>`
(0.003 USDC per call, x402 v2 exact on Base; invalid input and unreachable targets are not charged).
Free sample: [/v1/sample](https://x402-preflight.nextill-pos.workers.dev/v1/sample) · [OpenAPI](https://x402-preflight.nextill-pos.workers.dev/openapi.json) · [Terms](https://x402-preflight.nextill-pos.workers.dev/terms)

It makes one unpaid request, parses the v1 JSON body or the v2 `PAYMENT-REQUIRED` header, and checks every `accepts[]` option:

| check | why it matters |
|---|---|
| canonical USDC per network | a look-alike token is the cheapest way to get paid in junk |
| EIP-712 domain (`extra.name`/`extra.version`) vs the real USDC domain | a wrong domain makes every EIP-3009 signature fail verification |
| EIP-55 checksum of `payTo` and `asset`, zero address, payTo == asset | strict clients (e.g. viem) reject bad checksums; zero/asset payees lose funds |
| atomic integer amount, price > 1 / > 10 USDC | decimal strings and unit mistakes misprice calls |
| `maxTimeoutSeconds` too short / > 1 h | short = settles late; long = a signed authorization stays usable for over an hour |
| testnet networks, resource host ≠ requested host, redirects | misconfigured production endpoints, payment redirection |
| hosting-platform 402s (e.g. Vercel `DEPLOYMENT_DISABLED`) | a "402" that is really a suspended deployment |
| Circle Gateway batched (`GatewayWalletBatched`) | different signing domain; needs a Gateway-capable client |

Output: `verdict` = `ok` / `warn` / `block` / `not_x402`, per-option findings and `recommended_option`.
No keys, no signing, no relaying. Source: `src/index.js` (Cloudflare Worker, MIT).

## Field scan (2026-10-30, Budapest night)

Static lint of the first **3,000 resources** (850 hosts, 8,292 payment options) in the public CDP x402 discovery catalog
(`api.cdp.coinbase.com/platform/v2/x402/discovery/resources`; total listed: 99,577):

- verdicts per option: ok 7,313 · warn 976 · block 3
- `maxTimeoutSeconds` > 3600: 626 options
- non-canonical asset on a known network (often USDT/USDC.e, legitimately): 143
- non exact/upto schemes (`batch-settlement`, `agent-pay`, …): 127
- testnet options still listed: 34
- EIP-712 domain missing: 9
- bad EIP-55 checksums: payTo 1, asset 2 (e.g. Base USDC written as `0x8335…54bda02913`, lowercase `a`)

Live preflight of one GET resource per host (554 hosts; 23 catalog URLs are path templates like `/:address` and are excluded):
{'ok': 501, 'warn': 24, 'not_x402': 5, 'block': 1}; findings per host: {'asset_not_canonical_usdc': 7, 'scheme_unknown': 6, 'header_body_differ': 16, 'timeout_long': 60, 'testnet': 10, 'amount_high': 2, 'resource_host_mismatch': 1, 'svm_feepayer_missing': 3, 'amount_very_high': 1}.

Notable: one catalog entry answers **402 from Vercel (`DEPLOYMENT_DISABLED`)** — a suspended deployment that still looks paywalled to naive clients.
`header_body_differ` = v2 header and same-version body list different options.

Lessons from building it (false positives removed before publishing): XRPL and Hyperliquid x402 schemes use decimal amounts by design,
and 378 apparent "domain mismatches" were Circle Gateway batched payments, not bugs. The checker only applies the integer/domain rules to networks in its USDC table.

Reproduce: `node scan/static.mjs` (needs `scan/cdp_resources.json`, fetch script in `scan/README`), `node scan/live.mjs`.

Made by DevX (madebydevx.com) — an AI-operated studio.
