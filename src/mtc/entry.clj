;; RFC 5.2.1 — MTCLogEntry and TBSCertificateLogEntry (what gets logged).
(ns mtc.entry
  "RFC Section 5.2.1: Log Entries.

  An issuance log entry is an MTCLogEntry (TLS presentation language):

    struct {
        MTCLogEntryExtension extensions<0..2^16-1>;  ; TLV list, sorted
        MTCLogEntryType type;                        ; null_entry(0) | tbs_cert_entry(1)
        select (type) { ... }
    } MTCLogEntry;

  For tbs_cert_entry, the payload is the DER contents octets of a
  TBSCertificateLogEntry (the fields of TBSCertificate minus signature
  and algorithm, with subjectPublicKeyInfoHash added):

    TBSCertificateLogEntry ::= SEQUENCE {
        version               [0] EXPLICIT Version DEFAULT v1,
        issuer                    Name,          ; CA ID as a DN
        validity                  Validity,
        subject                   Name,
        subjectPublicKeyAlgorithm AlgorithmIdentifier{...},
        subjectPublicKeyInfoHash  OCTET STRING,  ; HASH of SPKI DER
        issuerUniqueID        [1] IMPLICIT UniqueIdentifier OPTIONAL,
        subjectUniqueID       [2] IMPLICIT UniqueIdentifier OPTIONAL,
        extensions            [3] EXPLICIT Extensions{{...}} OPTIONAL }

  subjectPublicKeyInfoHash = HASH over the SubjectPublicKeyInfo DER.
  MTCLogEntry size MUST NOT exceed 65535 bytes.")

;; (defn encode-mtc-log-entry [extensions type payload] ...)
;; (defn decode-mtc-log-entry [bytes] ...)
;; (defn encode-tbs-cert-log-entry [{:keys [version issuer validity subject
;;                                          subject-public-key-algorithm
;;                                          subject-public-key-info-hash
;;                                          issuer-unique-id subject-unique-id
;;                                          extensions]}] ...)
