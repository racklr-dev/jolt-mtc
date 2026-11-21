;; RFC 7 — relying-party verification.
(ns mtc.relying-party
  "RFC Section 7.2: verifying a Merkle Tree Certificate signature.

  This namespace implements the Merkle/log part of certificate
  verification (steps 3-12 of RFC 7.2).  Building the full X.509
  TBSCertificateLogEntry from a parsed X.509 Certificate is out of scope
  here: the caller supplies the serial number, the decoded MTCProof, and
  the encoded MTCLogEntry, which RFC 7.2 would otherwise assemble in a
  single pass from the DER TBSCertificate.

  config keys:
    :ca-id              PEN-relative CA trust anchor ID arcs (e.g. [32473 1])
    :trusted-subtrees   [{:log-number :start :end :hash}]  (landmark path)
    :cosigner-verifiers [{:cosigner-id arcs :public-key ... :verify-fn f}]
    :cosigner-policy    (fn [valid-cosigner-id-arcs] -> bool)
    :revoked-ranges     [[start end) ...] serial ranges (optional)"
  (:require [mtc.bit :as bit]
            [mtc.merkle :as m]
            [mtc.subtree :as st]
            [mtc.cosigner :as cos]))

(defn log-id
  "The issuance log's trust anchor ID: ca-id arcs + 0 + log-number (RFC 5.2)."
  [ca-id log-number]
  (conj (vec ca-id) 0 log-number))

(defn- in-ranges? [serial ranges]
  (boolean
    (some (fn [[s e]] (and (bit/u64-<= (bit/u64 s) serial)
                           (bit/u64-<= serial (bit/u64 (unchecked-subtract e 1)))))  ; [s, e)
          ranges)))

(defn verify
  "Verify the MTC portion of a certificate signature. Returns true/false.
  serial is a uint64 (Long); mtc-proof is a decoded MTCProof; entry is the
  encoded MTCLogEntry bytes."
  [{:keys [ca-id trusted-subtrees cosigner-verifiers cosigner-policy revoked-ranges]}
   serial mtc-proof entry]
  (try
    (let [serial (bit/u64 serial)
          _ (when (seq revoked-ranges)
              (when (in-ranges? serial revoked-ranges)
                (throw (ex-info "serial revoked" {}))))
          index (bit-and serial 0xFFFFFFFFFFFF)
          log-number (unsigned-bit-shift-right serial 48)
          _ (when (zero? log-number)
              (throw (ex-info "log number zero" {})))
          log-id (log-id ca-id log-number)
          entry-hash (m/leaf-hash entry)
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
