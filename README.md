# Merkle Tree Certificates — a jolt library

> **⚠ Experimental.** This implements
> [`draft-ietf-plants-merkle-tree-certs-08`](https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-08.txt)
> (November 2026), an *Internet-Draft*, not a published RFC. The wire format
> and OIDs can still change between drafts. Do **not** use it for anything you
> would not be comfortable losing. Treat it as a reference implementation and
> a playground for building Merkle Tree Certificate tooling.

Merkle Tree Certificates (MTC) are X.509 certificates whose signature is an
**inclusion proof** into an append-only issuance log, plus a quorum of
cosignatures over that log's subtrees. This library implements the full
normative surface of the draft — subtrees, logs, certificates, landmarks,
cosigners, quorum policies, revocation, and verification — as pure Clojure
that runs on [jolt](https://github.com/jolt-lang/jolt) (Clojure on Chez Scheme,
no JVM), and as standalone native binaries.

## Use

```clojure
;; deps.edn
{:deps {racklr-dev/jolt-mtc
        {:git/url "https://github.com/racklr-dev/jolt-mtc"
         :git/sha "b5fcb09f2281b528398766e3d739730aec1f6c12"}}}
```

```clojure
(require '[mtc.log]
         '[mtc.certificate]
         '[mtc.relying-party])
```

`jolt-mtc` composes two smaller reusable libraries, which come along
automatically as git deps: `racklr-dev/jolt-merkle` (RFC9162 trees + subtrees)
and `racklr-dev/jolt-x509` (DER + X.509).

## Quickstart

Make your first self-signed Merkle Tree Certificate in three commands.
You need a [jolt](https://github.com/jolt-lang/jolt) binary on your `PATH`
(`jolt --version`).

```bash
# 1. build the CLI (needs the :crypto alias for real Ed25519 keys)
JOLT_SKIP_MIN_VERSION=1 jolt -A:crypto build -m mtc.cli -o mtc-cli

# 2. issue a self-signed MTC for a name — generates a keypair, writes PEM files
./mtc-cli issue web.example.com
# => issued self-signed MTC for web.example.com
# =>   cert:   web.example.com.crt
# =>   key:    web.example.com.key
# =>   serial: 281474976710656
# =>   self-verified: true

# 3. any X.509 tool can parse it (though only this library verifies it)
openssl x509 -in web.example.com.crt -noout -subject -serial
# => subject=CN=web.example.com
# => serial=01000000000000
```

Prefer to run without compiling? The same command works interpreted:
`jolt -A:crypto run -m mtc.cli issue web.example.com`.

## Concepts in sixty seconds

* **Issuance log** — an append-only Merkle tree of every certificate a CA has
  issued. Its root is the CA's checkpoint.
* **Subtree** — a contiguous range of log entries, identified by `[start, end)`.
* **Inclusion proof** — the hashes proving one entry is inside a subtree; this
  is what replaces the CA signature in a Merkle Tree Certificate.
* **Cosigner** — a party that signs a subtree. The CA cosigner provides
  authenticity; additional **witness** cosigners provide transparency and
  each follow their own view of the log, refusing forks.
* **Quorum** — the set of cosignatures a relying party requires before it
  trusts a subtree (e.g. "the CA plus at least 2 witnesses").
* **Landmark** — a named, expired snapshot of the log that lets certificates
  be issued later against a larger, predistributed subtree — smaller proofs,
  no per-certificate cosignatures.
* **serialNumber** — `(log_number << 48) | entry_index`.

## What you can use it for

### 1. A self-signing certificate authority

`mtc.ca-server` is a deployable CA that persists its log and signing key and
issues standalone certificates on demand:

```bash
MTC_DATA_DIR=/data jolt -A:server run -m mtc.ca-server

# issue a certificate for a subject
curl -X POST localhost:8080/issue -d '{"subject":"web.example.com"}'
# => {"index":0,"serial":281474976710656,"root":"…"}

curl localhost:8080/cert/0 -o cert.pem      # the X.509 certificate
curl localhost:8080/key/0  -o key.pem       # the matching private key
```

OpenSSL can parse the result — `openssl x509 -in cert.pem -noout -text` shows
the trust-anchor-ID issuer, the `id-alg-mtcProof` signature algorithm, and the
Ed25519 subject key. It cannot *verify* it: that is what this library is for.

### 2. Transparency via a cosigner quorum

A CA alone can lie about its log. The draft's answer is additional
witness/mirror cosigners that each follow their own append-only view of the
log and only sign subtrees consistent with it:

```bash
MTC_COSIGNER_ID=32473.1.101 MTC_CA_URL=http://ca:8080 jolt -A:server run -m mtc.cosigner-server
```

The CA (`MTC_COSIGNERS=…, MTC_QUORUM=2`) collects witness cosignatures over
HTTP into every certificate, and the verifier accepts a certificate only when
the CA *and* a quorum of witnesses signed. A witness refuses to sign if the
CA's checkpoint no longer matches the witness's own view — i.e. a fork.

### 3. A verification sidecar in front of a proxy

The same service verifies presented certificates. It plugs into two widely
used proxies without changing them:

* **nginx** — `auth_request`:

  ```nginx
  location = /auth {
    internal;
    proxy_pass http://mtc:8080/auth;
    proxy_set_header X-Client-Cert $http_x_mtc_cert;
  }
  location /protected {
    auth_request /auth;
    root /site; index index.html;
  }
  ```

* **envoy** — `ext_authz` (HTTP service):

  ```yaml
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      allowed_headers:
        patterns: [{ exact: x-mtc-cert }]
      http_service:
        server_uri: { uri: http://mtc:8080, cluster: ext_authz_cluster, timeout: 5s }
        path_prefix: /ext_authz
  ```

Both are proven end-to-end in `demo/`: with a valid MTC certificate the proxy
serves the page (200); without one it returns 401.

### 4. A command-line tool

`mtc.cli` compiles to a single self-contained binary. Its `issue` subcommand
creates a self-signed MTC in one step — generate a real Ed25519 keypair,
self-sign, and write the PEM files:

```bash
JOLT_SKIP_MIN_VERSION=1 jolt -A:crypto build -m mtc.cli -o mtc-cli

mtc-cli issue web.example.com           # -> web.example.com.crt + .key
mtc-cli issue web.example.com /tmp/web  # choose the output prefix
mtc-cli demo 7                          # fixed 20-entry demo
```

### 5. As a Clojure library

The core is dependency-free. Add it to a consumer project and call the
namespaces directly:

```clojure
{:deps {mtc {:local/root "../mtc"}}}
```

```clojure
(require '[mtc.log] '[mtc.certificate] '[mtc.relying-party])
```

## Repositories

This repo (`jolt-mtc`) composes two smaller reusable libraries as jolt-style
git deps:

| Repo | Namespaces |
|---|---|
| `racklr-dev/jolt-merkle` | `jolt.bit`, `jolt.sha256`, `jolt.merkle`, `jolt.subtree`, `jolt.covering` |
| `racklr-dev/jolt-x509` | `jolt.der`, `jolt.tls`, `jolt.x509` |

## Layout

```
jolt-mtc/
  src/mtc/
    entry, tbs          MTCLogEntry/TBSCertificateLogEntry; TBS -> entry bridge
    log                 append-only issuance log (persistent)
    cosigner, sig       CosignedSubtree; real Ed25519/ECDSA/RSA via jolt-crypto
    certificate         MTCProof/Cosignature, serialNumber, GREASE
    ca                  MTCCertificationAuthority extension
    landmarks           landmark sequences, publish format, landmark-relative certs
    anchors, iana       trust-anchor IDs, TLS trust_anchors, IANA registries
    acme                ACME link relation + content type
    policy              cosigner policies (quorum)
    relying-party       verification (full DER cert + single-pass hash)
    service            HTTP verification sidecar
    ca-server          deployable self-signing CA (+ revocation)
    cosigner-server    standalone witness cosigner
    cli                demo CLI
  test/mtc/            20+ test scripts, incl. the RFC's own vectors
  demo/                nginx / envoy / quorum podman demos
```

## Cryptography

The core is pure Clojure and needs nothing at runtime. Real signatures come
from [jolt-lang/crypto](https://github.com/jolt-lang/crypto) (OpenSSL 3) and
are opt-in:

* `jolt -A:crypto …` — pulls jolt-crypto (Ed25519/ECDSA/RSA) for `mtc.sig`.
* `jolt -A:server …` — crypto + `ring-chez-adapter` (HTTP) + `jolt.http-client`.

jolt-crypto currently declares `:jolt/min-version 0.8.0`; on a jolt build that
reports an older version but has the needed runtime, set
`JOLT_SKIP_MIN_VERSION=1`.

## Building binaries

`jolt build` turns any namespace with a `-main` into a standalone native
binary (no JVM, no runtime):

```bash
jolt build -m mtc.cli -o mtc-bin          # pure core
jolt -A:server build -m mtc.ca-server -o mtc-ca   # CA service
jolt -A:server build -m mtc.cosigner-server -o mtc-cosigner
```

These binaries need only a C library (`glibc`) plus, for `-A:server`, OpenSSL 3
and zlib/zstd at runtime — the `demo/*.Containerfile`s install exactly those.

The default build targets the host. `--target <machine>` cross-compiles for
another Chez Scheme machine once you've prepared a target pack (see
jolt's `tools/cross-compile`):

| Machine | Platform |
|---|---|
| `ta6le` | x86-64 Linux |
| `ta6nt` | x86-64 Windows |
| `ta6osx` | x86-64 macOS |
| `tarm64le` | ARM64 Linux |
| `tarm64osx` | ARM64 macOS (Apple Silicon) |
| `a6le` | ARMv7 Linux |
| `i3le` | x86 (32-bit) Linux |

Other Chez machine types are available too. Caveat: cross-compiling a binary
that carries `:jolt/native` libraries (crypto, http-client) is not yet
supported — those must be present on the target host and loaded at runtime.

## Running the demos

```bash
cd mtc

# demo website: CA + nginx site, cert -> 200, none -> 401
bash demo/run-site-demo.sh

# quorum: CA + 3 witnesses (quorum 2) + nginx site
bash demo/run-quorum-demo.sh

# envoy ext_authz
bash demo/run-envoy-demo.sh
```

All three use podman. (`podman play kube` needs `catatonit` on `$PATH`; the
scripts use `podman run` on a shared network instead.)

## Verification

```bash
cd mtc
for t in test/mtc/*_test.clj; do jolt run "$t"; done
```

The suite includes the draft's own test vectors (Appendix C: accumulated
hashes, large-tree validity/covering, SHA-256 KATs) plus round-trip and
negative tests for every layer.

## Status and honest limits

Implemented and tested: the full normative surface — subtree proofs, logs,
entries, cosigners, quorum policies, certificates, landmark sequences and
landmark-relative certificates, revocation ranges, the TLS trust_anchors
extension, and the ACME/IANA constants — plus working nginx and envoy
integrations and a multi-witness deployment.

Not here (deliberately): TLS-stack code that can *natively* verify MTC certs
inside a handshake (RFC §8's custom verifier is the right home for that, and
stock OpenSSL/nginx/envoy reject `id-alg-mtcProof` certs as transport certs),
and the §12.2.1 log-failure recovery flow, which is defined by the
`trust-anchor-ids` draft rather than this one.

## Where to go next

* The spec: [`draft-ietf-plants-merkle-tree-certs-08`](https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-08.txt) —
  and its sibling [`draft-ietf-tls-trust-anchor-ids`](https://www.ietf.org/archive/id/draft-ietf-tls-trust-anchor-ids-07.txt),
  which defines trust-anchor IDs and the `trust_anchors` TLS extension.
* The code: `src/mtc/` is small and commented; `mtc.relying-party/verify` and
  `mtc.ca-server/issue!` are the best two entry points to read first.
* The demos: `demo/run-quorum-demo.sh` (CA + 3 witnesses + nginx) is the
  richest end-to-end example.
* [jolt](https://github.com/jolt-lang/jolt) and its
  [docs](https://jolt-lang.net/docs/getting-started.html) — how the Clojure-on-Chez runtime and
  `jolt build` work.
