;; RFC 7 — relying-party verification.
(ns mtc.relying-party
  "RFC Section 7: Relying Parties.

  A relying party is configured with trusted cosigners (7.3), trusted
  subtrees (7.4, for landmark-relative certs), and revoked ranges (7.5).
  It verifies a Merkle Tree Certificate by:

    - checking the serial number is outside revoked ranges (7.5),
    - recomputing the entry hash and evaluating the inclusion proof
      (RFC 4.3.2) against the subtree hash,
    - checking the subtree hash is cosigned by enough trusted cosigners
      (standalone) or is a trusted landmark subtree (landmark-relative).

  RFC 7.2's single-pass construction: the TBSCertificateLogEntry is
  decoded field-by-field (issuer, validity, subject, SPKI algorithm,
  SPKI hash, extensions), then the cert's TBSCertificate is verified to
  match it and the SPKI hash.")

;; (defn trusted-cosigners [config] ...)
;; (defn trusted-subtrees [config ca-log-id] ...)
;; (defn verify-certificate [config cert] ...)  ; -> {:ok ...} or throws/fails
