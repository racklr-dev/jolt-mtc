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
  src/mtc/                  the library namespaces (one per RFC concern)
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
- `mtc.sig` — real signature algorithms (Ed25519/ECDSA/RSA) via jolt-lang/crypto
- `mtc.certificate` — MTCProof/Cosignature + serialNumber (RFC 6)
- `mtc.ca` — MTCCertificationAuthority + its X.509 Extension (RFC 5.5)
- `mtc.landmarks` — landmark sequences + strict publish format (RFC 6.4)
- `mtc.anchors` — trust anchor IDs + the TLS trust_anchors extension (RFC 5.1/8)
- `mtc.acme` — ACME link relation + content type (RFC 9)
- `mtc.iana` — the RFC 13 IANA OIDs and registry values
- `mtc.x509` — Name/Validity/AlgorithmIdentifier codec + Certificate/TBSCertificate parser
- `mtc.relying-party` — certificate verification, including full DER cert
  (verify-certificate, RFC 7.2)

Cryptography is opt-in: the pure Merkle/log/certificate core has no
runtime dependencies, and `mtc.sig` pulls real signature algorithms
(Ed25519/ECDSA/RSA) and full X.509 parsing from
[jolt-lang/crypto](https://github.com/jolt-lang/crypto) (OpenSSL) behind the
`:crypto` alias (`jolt -A:crypto ...`).

TLS (RFC 8) and ACME (RFC 9) wire integration are the consumer's transport
concern, not part of this certificate library: the library produces and
verifies the certificate structures those protocols carry.
