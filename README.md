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

Status: **full RFC implementation (subtree core + log/certificate layer).**

Namespaces (all passing `jolt run test/mtc/<test>.clj`):

- `mtc.bit`, `mtc.sha256`, `mtc.merkle`, `mtc.subtree`, `mtc.covering` —
  RFC 4 + Appendix B/C, verified against the RFC's accumulated and
  large-tree test vectors
- `mtc.der` — minimal DER (INTEGER/OCTET STRING/OID/SEQUENCE/NULL/context)
- `mtc.tls` — big-endian TLS presentation primitives
- `mtc.entry` — MTCLogEntry + TBSCertificateLogEntry (RFC 5.2.1)
- `mtc.log` — append-only issuance log with incremental Merkle tree head
- `mtc.cosigner` — CosignedSubtree sign/verify (RFC 5.3)
- `mtc.certificate` — MTCProof/Cosignature + serialNumber (RFC 6)
- `mtc.ca` — MTCCertificationAuthority (RFC 5.5)
- `mtc.landmarks` — landmark sequences + strict publish format (RFC 6.4)
- `mtc.x509` — Name/Validity/AlgorithmIdentifier codec + Certificate/TBSCertificate parser
- `mtc.relying-party` — certificate verification, including full DER cert
  (verify-certificate, RFC 7.2)

Out of scope (documented): the full RFC5280 Name/value surface (only
UTF8/Printable/IA5 strings, UTCTime/GeneralizedTime), the trust-anchor-ID
DN construction, TLS/ACME wire integration, and concrete signature
algorithms (the cosigner sign/verify seam is pluggable).
