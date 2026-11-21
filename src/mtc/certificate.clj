;; RFC 6 — the certificate format (MTCProof) and construction.
(ns mtc.certificate
  "RFC Section 6: Certificates.

  A Merkle Tree Certificate is an X.509 Certificate whose signatureValue
  is an MTCProof (no ASN.1 wrapping), with signatureAlgorithm OID
  id-alg-mtcProof (1.3.6.1.5.5.7.6.67):

    struct {
        MTCLogEntryExtension extensions<0..2^16-1>;
        uint48 start; uint48 end;
        opaque inclusion_proof<0..2^16-1>;   ; concatenated hashes
        Cosignature signatures<0..2^24-1>;
    } MTCProof;
    struct {
        TrustAnchorID cosigner_id;
        opaque signature<0..2^16-1>;
    } Cosignature;

  serialNumber = (log_number << 48) | index  (RFC 6.2), so it is always
  positive and <= 2^64-1.  signatures must have unique cosigner_ids,
  ordered by (length, then lexicographic) — a parser MUST reject
  duplicates or wrong order.")

;; (defn serial-number [log-number index] ...)  ; (bit-or (bit-shift-left log-number 48) index)
;; (defn encode-mtc-proof [{:keys [extensions start end inclusion-proof signatures]}] ...)
;; (defn decode-mtc-proof [bytes] ...)  ; strict: dup/order checks, uint48 bounds
;; (defn construct-standalone-certificate [...] ...)
;; (defn construct-landmark-relative-certificate [...] ...)
