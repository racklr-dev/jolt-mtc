;; RFC 13 — IANA registrations for Merkle Tree Certificates.
(ns mtc.iana
  "RFC Section 13: the OIDs, link relation, content type and registry values
  Merkle Tree Certificates registers. Kept as data so the rest of the library
  and consumers share one spelling.")

;; 13.1.2 — Algorithm
(def id-alg-mtc-proof [1 3 6 1 5 5 7 6 67])

;; 13.1.3 — Certificate Extension
(def id-pe-mtc-ca-sha256 [1 3 6 1 5 5 7 1 38])

;; trust-anchor-ids draft — RDN attribute type
(def id-rdna-trust-anchor-id [1 3 6 1 5 5 7 25 3])

;; 13.1.4 — Link Relation Type
(def link-relation-acme-optional-alternate "acme-optional-alternate")

;; 9.2 — ACME content type for CertificatePropertyList-bearing chains
(def content-type-pem-cert-chain-with-properties
  "application/pem-certificate-chain-with-properties")

;; 13.2.1 — MTC Log Entry Types
(def log-entry-type-null 0)
(def log-entry-type-tbs-cert 1)
(def log-entry-type-private-use-start 0xF000)
(def log-entry-type-private-use-end 0xFFFF)

;; 13.2.2 — MTC Log Entry Extension Types
(def extension-type-private-use-start 0xF000)
(def extension-type-private-use-end 0xFFFF)

;; 13.2.3 — MTC CA Identifier Child Components
(def ca-id-child-logs 0)
(def ca-id-child-landmarks 1)
(def ca-id-child-landmark-groups 2)
