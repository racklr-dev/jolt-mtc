;; Bridge between a parsed X.509 TBSCertificate and a TBSCertificateLogEntry
;; (RFC 7.2 steps 7-9). These were once in mtc.x509; they live here because they
;; know about MTC log entries (mtc.entry), which the reusable jolt-x509 must not.
(ns mtc.tbs
  (:require [jolt.x509 :as x]
            [jolt.merkle :as m]
            [mtc.entry :as entry]))

(defn- slice [bytes off len]
  (let [out (byte-array len)]
    (dotimes [i len] (aset out i (aget bytes (+ off i))))
    out))

(defn mtc-proof-alg-id?
  "True when a DER AlgorithmIdentifier is id-alg-mtcProof with parameters
  omitted (RFC 6.2 / 7.2 step 1)."
  [alg-id-der]
  (let [[oid params] (x/decode-alg-id alg-id-der)]
    (and (= [1 3 6 1 5 5 7 6 67] oid) (nil? params))))

(defn mtc-proof-bytes
  "The MTCProof bytes inside a certificate's signatureValue BIT STRING
  (drop the leading unused-bits count byte)."
  [cert]
  (let [sv (:signature-value cert)]
    (slice sv 1 (- (alength sv) 1))))

(defn entry-map-from-tbs
  "Build the mtc.entry TBSCertificateLogEntry map from a parsed TBSCertificate
  (RFC 7.2 step 7): copy version/issuer/validity/subject/unique-ids/extensions,
  take the SPKI algorithm, and hash the SPKI."
  [hash-fn tbs]
  {:version (:version tbs)
   :issuer (:issuer tbs)
   :validity (:validity tbs)
   :subject (:subject tbs)
   :subject-public-key-algorithm (:spki-algorithm tbs)
   :subject-public-key-info-hash (hash-fn (:spki tbs))
   :issuer-unique-id (:issuer-unique-id tbs)
   :subject-unique-id (:subject-unique-id tbs)
   :extensions (:extensions tbs)})

(defn mtc-log-entry-bytes-from-tbs
  "Build the MTCLogEntry bytes from a parsed TBSCertificate (RFC 7.2 steps 7-8)."
  [hash-fn tbs extensions]
  (entry/encode-mtc-log-entry extensions entry/tbs-cert-entry
                               (entry/encode-tbs-cert-log-entry-fields
                                 (entry-map-from-tbs hash-fn tbs))))

(defn entry-hash-from-tbs
  "RFC 7.2 step 9, computed as the single-pass sequence: HASH(0x00 || entry).
  hash-fn hashes the SPKI; the outer leaf hash is SHA-256."
  [hash-fn tbs extensions]
  (m/leaf-hash (mtc-log-entry-bytes-from-tbs hash-fn tbs extensions)))
