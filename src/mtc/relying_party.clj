;; RFC 7 — relying-party verification.
(ns mtc.relying-party
  "RFC Section 7.2: verifying a Merkle Tree Certificate signature.

  verify takes a decoded MTCProof and the encoded MTCLogEntry; verify-certificate
  takes a full DER X.509 Certificate, parses its TBSCertificate, constructs the
  TBSCertificateLogEntry / MTCLogEntry (RFC 7.2 steps 7-8), and verifies.

  config keys:
    :ca-id              PEN-relative CA trust anchor ID arcs (e.g. [32473 1])
    :trusted-subtrees   [{:log-number :start :end :hash}]  (landmark path)
    :cosigner-verifiers [{:cosigner-id arcs :public-key ... :verify-fn f}]
    :cosigner-policy    (fn [valid-cosigner-id-arcs] -> bool)
    :revoked-ranges     [[start end) ...] serial ranges (optional)"
  (:require [mtc.bit :as bit]
            [mtc.merkle :as m]
            [mtc.subtree :as st]
            [mtc.cosigner :as cos]
            [mtc.certificate :as cert]
            [mtc.x509 :as x]
            [mtc.sha256 :as sha]))

(defn log-id
  "The issuance log's trust anchor ID: ca-id arcs + 0 + log-number (RFC 5.2)."
  [ca-id log-number]
  (conj (vec ca-id) 0 log-number))

(defn- in-ranges? [serial ranges]
  (boolean
    (some (fn [[s e]] (and (bit/u64-<= (bit/u64 s) serial)
                           (bit/u64-<= serial (bit/u64 (unchecked-subtract e 1)))))
          ranges)))

(defn- verify-core
  "RFC 7.2 steps 3-12, given the serial number, decoded MTCProof and entry hash."
  [{:keys [ca-id trusted-subtrees cosigner-verifiers cosigner-policy revoked-ranges]}
   serial mtc-proof entry-hash]
  (try
    (let [serial (bit/u64 serial)
          _ (when (and (seq revoked-ranges) (in-ranges? serial revoked-ranges))
              (throw (ex-info "serial revoked" {})))
          index (bit-and serial 0xFFFFFFFFFFFF)
          log-number (unsigned-bit-shift-right serial 48)
          _ (when (zero? log-number)
              (throw (ex-info "log number zero" {})))
          log-id (log-id ca-id log-number)
          start (:start mtc-proof)
          end (:end mtc-proof)
          expected (st/evaluate-inclusion-proof start end index entry-hash
                                                 (:inclusion-proof mtc-proof))
          trusted (some (fn [t] (when (and (= log-number (:log-number t))
                                           (= start (:start t))
                                           (= end (:end t)))
                                  t))
                        trusted-subtrees)]
      (if trusted
        (m/bytes= expected (:hash trusted))
        (let [valid (for [{:keys [cosigner-id signature]} (:signatures mtc-proof)
                          :let [arcs (cos/cosigner-id-arcs cosigner-id)
                                v (some (fn [cv] (when (= arcs (:cosigner-id cv)) cv))
                                        cosigner-verifiers)]
                          :when v
                          :let [cst {:cosigner-name (cos/trust-anchor-name arcs)
                                     :timestamp 0
                                     :log-origin (cos/trust-anchor-name log-id)
                                     :start start
                                     :end end
                                     :subtree-hash expected}]
                          :when (cos/verify (:verify-fn v) (:public-key v) cst signature)]
                      arcs)]
          (boolean (cosigner-policy valid)))))
    (catch Throwable _ false)))

(defn verify
  "Verify the MTC portion of a certificate given a decoded MTCProof and the
  encoded MTCLogEntry bytes. serial is a uint64."
  [config serial mtc-proof entry]
  (verify-core config serial mtc-proof (m/leaf-hash entry)))

(defn verify-certificate
  "Verify a full DER X.509 Merkle Tree Certificate (RFC 7.2): parse the
  TBSCertificate, reconstruct the entry, evaluate the inclusion proof, and
  check trusted-subtree or cosigner policy."
  [config cert-der]
  (try
    (let [cert (x/parse-certificate cert-der)
          tbs (x/parse-tbs-certificate (:tbs-certificate cert))
          ca-id (x/decode-trust-anchor-name (:issuer tbs))
          serial (:serial-number tbs)
          mtc-proof (cert/decode-mtc-proof (x/mtc-proof-bytes cert))
          entry-hash (x/entry-hash-from-tbs sha/digest tbs (:extensions mtc-proof))]
      (verify-core (assoc config :ca-id ca-id) serial mtc-proof entry-hash))
    (catch Throwable _ false)))
