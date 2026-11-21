;; RFC 5.4 / 5.5 — the CA cosigner and its X.509 representation.
(ns mtc.ca
  "RFC Sections 5.4 and 5.5: Certification Authority Cosigners.

  Each CA operates a CA cosigner whose cosigner ID equals its CA ID.
  Signing a subtree certifies every entry in it (null_entry is a no-op;
  tbs_cert_entry certifies the TBSCertificateLogEntry).  A CA MUST NOT
  sign a subtree containing an entry type/extension it does not
  recognize.

  The CA is represented in an X.509 certificate with subject = CA ID as
  a DN, SPKI = cosigner public key, and a critical extension carrying

    MTCCertificationAuthority ::= SEQUENCE {
        sigAlg    AlgorithmIdentifier{...},
        minSerial INTEGER (2^48..2^64-1),
        maxSerial INTEGER (2^48..2^64-1) }

  (OID id-pe-mtcCertificationAuthority-SHA256 = 1.3.6.1.5.5.7.1.38.)
  minSerial/maxSerial bound the serial-number space used by the revoked-
  ranges mechanism (RFC 7.5).")

;; (def ca-id ...)                       ; trust anchor ID (OID arcs)
;; (defn certify-subtree! [log start end private-key] ...) ; CA cosign
;; (defn encode-mtc-ca-extension [{:keys [sig-alg min-serial max-serial]}] ...)
;; (defn min-serial [ca] ...) (defn max-serial [ca] ...)
