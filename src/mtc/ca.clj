;; RFC 5.4 / 5.5 — the CA cosigner and its X.509 representation.
(ns mtc.ca
  "RFC Sections 5.4 and 5.5: Certification Authority Cosigners.

  Each CA operates a CA cosigner whose cosigner ID equals its CA ID.
  Signing a subtree certifies every entry in it (null_entry is a no-op;
  tbs_cert_entry certifies the TBSCertificateLogEntry).

  The CA's X.509 certificate carries a critical extension whose extnValue
  is the DER of

    MTCCertificationAuthority ::= SEQUENCE {
        sigAlg    AlgorithmIdentifier{SIGNATURE-ALGORITHM, {...}},
        minSerial INTEGER (2^48..2^64-1),
        maxSerial INTEGER (2^48..2^64-1) }

  (OID id-pe-mtcCertificationAuthority-SHA256 = 1.3.6.1.5.5.7.1.38.)
  Building the full X.509 Certificate is out of scope; this namespace
  encodes/decodes the extension's value structure."
  (:require [mtc.der :as der]))

(def mtc-ca-sha256-oid
  "id-pe-mtcCertificationAuthority-SHA256"
  [1 3 6 1 5 5 7 1 38])

(defn encode-mtc-ca
  "DER-encode an MTCCertificationAuthority. Keys: :sig-alg (opaque DER
  AlgorithmIdentifier), :min-serial :max-serial (integers)."
  [{:keys [sig-alg min-serial max-serial]}]
  (der/encode [:seq [:raw sig-alg] [:int min-serial] [:int max-serial]]))

(defn- slice [bytes off len]
  (let [out (byte-array len)]
    (dotimes [i len] (aset out i (aget bytes (+ off i))))
    out))

(defn decode-mtc-ca
  "Decode a DER MTCCertificationAuthority into the same keyed map."
  [bytes]
  (when-not (= 0x30 (bit-and (aget bytes 0) 0xFF))
    (throw (ex-info "MTCCertificationAuthority must be a SEQUENCE" {})))
  (let [[_ outer-body _] (der/read-tlv bytes 0)]
    (loop [off 0 acc {}]
      (if (>= off (alength outer-body))
        acc
        (let [[ftag fbody fend] (der/read-tlv outer-body off)
              field (slice outer-body off (- fend off))]
          (case ftag
            0x30 (recur fend (assoc acc :sig-alg field))
            0x02 (if (contains? acc :min-serial)
                   (recur fend (assoc acc :max-serial (der/decode-int fbody)))
                   (recur fend (assoc acc :min-serial (der/decode-int fbody))))
            (throw (ex-info "unexpected MTCCertificationAuthority field tag" {:tag ftag}))))))))
