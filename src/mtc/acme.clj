;; RFC 9 — ACME integration.
(ns mtc.acme
  "RFC Section 9: using Merkle Tree Certificates with ACME.

  The ACME server serves the standalone certificate at the order's
  certificate URL, and advertises the landmark-relative certificate through
  an 'acme-optional-alternate' link relation (RFC 9.1), returning HTTP 202
  with Retry-After until the next landmark is allocated (RFC 9.2).

  The wire content types and link relation are constants; the
  CertificatePropertyList structure itself is defined in the
  trust-anchor-ids draft, not here."
  (:require [mtc.iana :as iana]))

(def link-relation
  "The 'acme-optional-alternate' link relation (RFC 9.1)."
  iana/link-relation-acme-optional-alternate)

(def content-type
  "application/pem-certificate-chain-with-properties (RFC 9.2)."
  iana/content-type-pem-cert-chain-with-properties)
