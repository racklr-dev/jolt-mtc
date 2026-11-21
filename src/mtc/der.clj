;; Minimal DER (X.690) encode/decode for the few ASN.1 fields MTC needs.
(ns mtc.der
  "Minimal DER encode/decode.

  We need just enough DER for TBSCertificateLogEntry (RFC 5.2.1) and
  MTCCertificationAuthority (RFC 5.5): SEQUENCE, INTEGER, OCTET STRING,
  OBJECT IDENTIFIER, and the Name/Validity pieces.  Not a general X.509
  codec — the full RFC5280 name encoding can be a later shim.

  DER basics: tag-length-value with definite short/long lengths,
  INTEGERs in two's complement minimal octets, OIDs as base-128 arcs.")

;; (defn encode-tlv [tag body] ...)
;; (defn encode-length [n] ...)
;; (defn encode-integer [n] ...)
;; (defn encode-octet-string [bytes] ...)
;; (defn encode-oid [arcs] ...)
;; (defn encode-sequence [& bodies] ...)
;; (defn decode-tlv [bytes] -> [tag body rest])
