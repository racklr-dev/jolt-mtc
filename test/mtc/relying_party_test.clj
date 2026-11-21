;; End-to-end: CA issues a standalone certificate, RP verifies.
;; Run: cd mtc && jolt run test/mtc/relying_party_test.clj
(ns mtc.test.relying-party
  (:require [mtc.log :as log]
            [mtc.entry :as entry]
            [mtc.certificate :as cert]
            [mtc.cosigner :as cos]
            [mtc.relying-party :as rp]
            [jolt.sha256 :as sha]
            [jolt.merkle :as m]))

(defn check [label expected got]
  (if (= expected got)
    (println (str "PASS " label))
    (do (println (str "FAIL " label)) (println (str "  expected " (pr-str expected))) (println (str "  got      " (pr-str got))) (System/exit 1))))

;; dummy signer: sig = sha256(key || msg)
(defn sign [key msg] (sha/digest (byte-array (concat (seq key) (seq msg)))))
(defn verify [key msg sig] (m/bytes= sig (sign key msg)))

(def cosigner-arcs [32473 1])
(def ca-key (.getBytes "ca-key" "UTF-8"))

;; CA side: an issuance log with 10 entries.
(def entries (vec (map (fn [i] (entry/encode-mtc-log-entry [] entry/tbs-cert-entry
                                                           (byte-array [i])))
                       (range 10))))
(def L (reduce log/append! (log/new-log 1) entries))

(def idx 5)
(def serial (cert/serial-number 1 idx))
(def proof (log/inclusion-proof L 0 10 idx))
(def entry (entries idx))

;; cosign the subtree [0, 10)
(def cst {:cosigner-name (cos/trust-anchor-name cosigner-arcs)
          :timestamp 0
          :log-origin (cos/trust-anchor-name (rp/log-id cosigner-arcs 1))
          :start 0 :end 10
          :subtree-hash (log/root-hash L)})
(def sig (cos/sign sign ca-key cst))

(def mtc-proof {:extensions []
                :start 0 :end 10
                :inclusion-proof proof
                :signatures [{:cosigner-id (cos/cosigner-id-bytes cosigner-arcs)
                              :signature sig}]})

(def config {:ca-id cosigner-arcs
             :trusted-subtrees []
             :cosigner-verifiers [{:cosigner-id cosigner-arcs :public-key ca-key :verify-fn verify}]
             :cosigner-policy (fn [ids] (some #{cosigner-arcs} ids))
             :revoked-ranges []})

(check "standalone cert verifies" true (rp/verify config serial mtc-proof entry))

;; wrong entry fails
(check "wrong entry fails" false (rp/verify config serial mtc-proof (entries 0)))

;; wrong serial (points at a different index) fails the inclusion proof
(check "wrong serial fails" false (rp/verify config (cert/serial-number 1 7) mtc-proof entry))

;; log number zero fails
(check "log 0 fails" false (rp/verify config 0 mtc-proof entry))

;; revoked range fails
(check "revoked fails" false (rp/verify (assoc config :revoked-ranges [[0 281474976710662]]) serial mtc-proof entry))

;; --- trusted-subtree path (landmark-relative certificate) -------------------
(def landmark-config (assoc config
                            :trusted-subtrees [{:log-number 1 :start 0 :end 10 :hash (log/root-hash L)}]
                            :cosigner-verifiers []))
(def landmark-proof (assoc mtc-proof :signatures []))
(check "landmark-relative verifies" true (rp/verify landmark-config serial landmark-proof entry))
(check "landmark-relative wrong subtree hash fails" false
       (rp/verify (assoc-in landmark-config [:trusted-subtrees 0 :hash] (byte-array 32))
                  serial landmark-proof entry))

(println "All relying-party tests passed")
