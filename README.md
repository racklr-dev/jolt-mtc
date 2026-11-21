# Merkle Tree Certificates (draft-ietf-plants-merkle-tree-certs-08) — jolt test libraries

A jolt library implementing the subtree/log/certificate algorithms of
[IETF Merkle Tree Certificates](https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-08.txt)
(draft-ietf-plants-merkle-tree-certs-08), built as testable pure functions.

Layout:

```
mtc/
  deps.edn                  jolt project (paths: src)
  PLAN.md                   how we tackle this in jolt
  rfc/
    draft-...-08.txt        the full RFC text
    sections/               the RFC split into per-section files
  src/mtc/                  stub namespaces (one per RFC concern)
  test/mtc/                 test scripts run with `jolt run`
```

Status: **§4 core implemented and verified against RFC Appendix C.**

Done and passing (`jolt run test/mtc/<test>.clj`):

- `mtc.bit` — bit/uint64 primitives
- `mtc.sha256` — pure-Clojure SHA-256 (FIPS 180-4 KATs)
- `mtc.merkle` — RFC9162 MTH + node-table + inclusion paths
- `mtc.subtree` — RFC 4 validity, inclusion/consistency proofs (generate + verify)
- `mtc.covering` — RFC 4.5 two-subtree covering

Validated: all four accumulated vectors (C.1.1–C.1.4), the C.2 large-tree
validity + covering vectors (up to 2^64-1), and proof verify/negative
cross-checks.

Still stubbed: `mtc.entry`, `mtc.log`, `mtc.cosigner`, `mtc.ca`,
`mtc.certificate`, `mtc.landmarks`, `mtc.relying-party`, `mtc.der`
(the log/certificate layer, RFC 5–7).
