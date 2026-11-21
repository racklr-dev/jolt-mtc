# Plan: implementing draft-ietf-plants-merkle-tree-certs-08 in jolt

Goal: a set of jolt test libraries that implement version 08 of IETF
Merkle Tree Certificates (MTC), verified against the RFC's own test
vectors (Appendix C).  jolt = Clojure on Chez Scheme.

## 1. What the RFC actually specifies

MTC is "CT-style logging, inverted": a CA certifies a statement by
appending it to an append-only issuance log and cosigning subtrees;
a certificate is a proof of inclusion in a cosigned subtree.

The implementable, self-contained core is the Merkle machinery:

- RFC 2: bit/int primitives (LSB, BIT_WIDTH, POPCOUNT, BIT_CEIL).
- RFC 4 + Appendix B: subtrees, inclusion proofs (4.3), consistency
  proofs (4.4), and the two-subtree interval cover (4.5).
- RFC 5.2: the issuance log (a RFC9162 Merkle Tree over entries).
- RFC 5.2.1: MTCLogEntry / TBSCertificateLogEntry (the logged thing).
- RFC 5.3: CosignedSubtree (cosignature format).
- RFC 6: certificate format — MTCProof, Cosignature, serialNumber =
  (log_number << 48) | index.
- RFC 6.4: landmark sequences and landmark-relative certificates.
- RFC 7: relying-party verification (single-pass signature check).

Out of scope for the first cut: TLS/ACME wire integration (RFC 8/9),
and the full X.509 ASN.1 machinery (we need only minimal DER for
TBSCertificateLogEntry fields, not a general X.509 codec).

## 2. jolt-specific constraints (verified)

1. **No SHA-256 provider.** `java.security.MessageDigest` is not
   provided by jolt's runtime ("No dependency provides
   java.security.MessageDigest").  We implement SHA-256 in pure
   Clojure (FIPS 180-4): it is ~100 lines over clojure.core bit ops.
   Verified jolt has: `bit-and/-or/-xor/-not`, `bit-shift-left`,
   `unsigned-bit-shift-right`, arbitrary-precision ints (`N` suffix).
   No `bit-rotate-left` (Clojure 1.11 fn) — implement rotation as
   `(bit-or (unsigned-bit-shift-right x k) (bit-shift-left x (- 32 k)))`.

2. **Bignums are native.** Tree sizes are uint48 (max 2^48-1) but
   Appendix C.2 exercises up to 2^64-1; jolt integers are arbitrary
   precision, so no overflow concern.

3. **Byte handling.** Keep the API byte-array based (jolt byte arrays
   work with `aget`/`aset` and `java.util.Arrays/copyOfRange`).  Encode
   test vectors as hex strings, matching Appendix C.

4. **DER is a dependency of the cert layer only.**  Implement a tiny
   DER encoder/decoder (`mtc.der`) for the specific fields of
   TBSCertificateLogEntry (SEQUENCE, INTEGER, OCTET STRING, OID,
   UTF8String/Name pieces) rather than a general codec.

## 3. Module breakdown (namespaces)

Pure, no-I/O core (implement first, everything else builds on it):

| ns | RFC | contents |
|---|---|---|
| `mtc.bit` | 2 | lsb, bit-width, popcount, bit-ceil, rotate32 |
| `mtc.sha256` | [SHS] | pure SHA-256: digest, hex |
| `mtc.merkle` | RFC9162 2.1.1 | empty-hash, leaf-hash, node-hash, MTH |
| `mtc.subtree` | 4 | valid-subtree?, subtree-hash, inclusion/consistency proof generate + verify |
| `mtc.covering` | 4.5 | find-subtrees (two-subtree interval cover) |

Protocol/data layer:

| ns | RFC | contents |
|---|---|---|
| `mtc.der` | — | minimal DER encode/decode |
| `mtc.entry` | 5.2.1 | MTCLogEntry + TBSCertificateLogEntry |
| `mtc.log` | 5.2 | issuance log: append, checkpoint, tree-size, entry index |
| `mtc.cosigner` | 5.3 | CosignedSubtree sign/verify |
| `mtc.ca` | 5.4/5.5 | CA cosigner, MTCCertificationAuthority, serial bounds |
| `mtc.certificate` | 6 | MTCProof, Cosignature, serialNumber, construct/parse |
| `mtc.landmarks` | 6.4 | landmark sequence + landmark subtrees + publish format |
| `mtc.relying-party` | 7 | certificate signature verification (single-pass) |

## 4. Implementation order (test-first)

1. `mtc.bit` — trivial, no deps.  Unit-test bit-width/popcount/bit-ceil
   against brute-force ground truth for n in 0..2^20.

2. `mtc.sha256` — test against FIPS 180-4 known answers ("abc", empty,
   "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", the
   1,000,000-"a" vector).  This is the correctness keystone.

3. `mtc.merkle` — test empty/leaf/node hashes by hand-computed vectors.

4. `mtc.subtree` + `mtc.covering` — the core.  Acceptance = Appendix C:
   - C.1.1 subtree hashes → `b82806ad...e3e81`
   - C.1.2 inclusion proofs → `ac2a8f98...d8163f`
   - C.1.3 consistency proofs → `10fa99b3...5a0a74`
   - C.1.4 covering subtrees → `7fd9c8b9...c8bb0`
   - C.2 large-tree vectors (validity + covering) for sizes up to 2^64-1
   Port the RFC's Python reference loops literally into a test script;
   the accumulated-vector technique (rolling sha256 over all small cases)
   makes the whole space testable in one run.

5. `mtc.der` + `mtc.entry` — DER round-trip tests on hand-rolled bytes.

6. `mtc.log`, `mtc.cosigner`, `mtc.certificate` — construct a fake CA
   log, issue a standalone certificate, parse it back; assert
   serialNumber = (log_number << 48) | index.

7. `mtc.landmarks` + `mtc.relying-party` — landmark-relative
   certificates; single-pass verification of both certificate kinds.

8. Negative tests from RFC C.1.2 steps 2-4: truncated/extended inclusion
   proofs must fail evaluation (one byte and one full hash, both ends).

## 5. Test harness

Run a test file with `jolt run test/mtc/<name>_test.clj` (jolt runs a
`.clj` script directly; the repo's own suites do the same).  Each test
script prints a line and exits non-zero on failure.  Prefer pure data
comparison (no test framework dependency) for the first pass.

## 6. Risks / open questions

- Pure-Clojure SHA-256 performance: fine for test vectors (sizes ≤ 130
  and single large trees), but a CA-scale log would want a native
  provider (`:jolt/native` + `:jolt/provides`) later.
- X.509 `Name`/`Validity`/`Extensions` DER in `mtc.entry`: keep to the
  fields the test vectors need; full RFC5280 name encoding is out of
  scope and can be a later shim.
- Cosigner signature algorithms (ML-DSA-44 etc.) are pluggable by
  cosigner ID; first cut can stub signature verification to a
  pluggable `(verify sigalg pub bytes sig)` protocol.
