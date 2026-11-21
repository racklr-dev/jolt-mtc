;; End-to-end demo: a CA issues a standalone + landmark-relative Merkle Tree
;; Certificate, and a relying party verifies it.
;; Run: cd mtc && jolt run examples/issue_verify.clj
(ns mtc.example.issue-verify
  (:require [clojure.string :as str]
            [mtc.der :as der]
            [mtc.entry :as entry]
            [mtc.log :as log]
            [mtc.certificate :as cert]
            [mtc.cosigner :as cos]
            [mtc.relying-party :as rp]
            [mtc.sha256 :as sha]
            [mtc.merkle :as m]))

(defn hex [b] (apply str (map (fn [x] (format "%02x" (bit-and x 0xff))) b)))

;; --- structured Name / Validity / AlgorithmIdentifier (inline for now) -----
(def cn-oid [2 5 4 3])
(defn- atv [oid value] [:seq [:oid oid] value])
(defn- rdn [oid s] [:set (atv oid [:utf8 s])])
(defn- make-name [& rdns] (into [:seq] rdns))

(def issuer  (der/encode (make-name (rdn cn-oid "MTC Test CA"))))
(def subject (der/encode (make-name (rdn cn-oid "example.com"))))
(def validity (der/encode [:seq [:utc "240101000000Z"] [:utc "260101000000Z"]]))
(def spki-alg (der/encode [:seq [:oid [1 2 840 113549 1 1 1]] [:null]]))
(def spki-hash (sha/digest (.getBytes "subject-public-key-info-DER" "UTF-8")))

(defn- tbs [i]
  (entry/encode-tbs-cert-log-entry
    {:issuer issuer
     :validity validity
     :subject (der/encode (make-name (rdn cn-oid (str "service-" i ".example.com"))))
     :subject-public-key-algorithm spki-alg
     :subject-public-key-info-hash spki-hash}))

(defn- log-entry [i] (entry/encode-mtc-log-entry [] entry/tbs-cert-entry (tbs i)))

;; --- CA: run an issuance log and append 20 entries --------------------------
(def entries (mapv log-entry (range 20)))
(def L (reduce log/append! (log/new-log 1) entries))

(defn check [label got]
  (println (str "  " label ": " (if got "ok" "FAIL")))
  (when-not got (System/exit 1)))

;; --- dummy cosigner ---------------------------------------------------------
(def cosigner-arcs [32473 1])
(def ca-key (.getBytes "ca-signing-key" "UTF-8"))
(defn sign [key msg] (sha/digest (byte-array (concat (seq key) (seq msg)))))
(defn verify [key msg sig] (m/bytes= sig (sign key msg)))

(defn cosign-subtree [start end]
  (let [cst {:cosigner-name (cos/trust-anchor-name cosigner-arcs)
             :timestamp 0
             :log-origin (cos/trust-anchor-name (rp/log-id cosigner-arcs 1))
             :start start :end end
             :subtree-hash (log/subtree-hash L start end)}]
    {:cosigner-id (cos/cosigner-id-bytes cosigner-arcs)
     :signature (cos/sign sign ca-key cst)}))

(def config {:ca-id cosigner-arcs
             :trusted-subtrees []
             :cosigner-verifiers [{:cosigner-id cosigner-arcs :public-key ca-key :verify-fn verify}]
             :cosigner-policy (fn [ids] (some #{cosigner-arcs} ids))
             :revoked-ranges []})

;; --- issue a standalone certificate for index 5 -----------------------------
(def idx 5)
(def serial (cert/serial-number 1 idx))
(def proof (log/inclusion-proof L 0 20 idx))

(println "== Merkle Tree Certificate issue + verify ==")
(println (str "log root hash:       " (hex (log/root-hash L))))
(println (str "entry index:         " idx))
(println (str "serial number:       " serial))
(println (str "inclusion proof:     " (count proof) " hashes"))

(def standalone {:extensions []
                 :start 0 :end 20
                 :inclusion-proof proof
                 :signatures [(cosign-subtree 0 20)]})

(check "standalone certificate verifies"
       (rp/verify config serial standalone (entries idx)))

;; --- landmark-relative certificate ------------------------------------------
(def landmark-config (assoc config
                            :trusted-subtrees [{:log-number 1 :start 0 :end 20
                                                :hash (log/root-hash L)}]
                            :cosigner-verifiers []))
(def landmark-proof (assoc standalone :signatures []))
(check "landmark-relative certificate verifies"
       (rp/verify landmark-config serial landmark-proof (entries idx)))

;; --- negatives --------------------------------------------------------------
(check "tampered entry rejected"
       (not (rp/verify config serial standalone (entries 0))))
(check "wrong serial rejected"
       (not (rp/verify config (cert/serial-number 1 7) standalone (entries idx))))
(check "revoked range rejected"
       (not (rp/verify (assoc config :revoked-ranges [[0 (+ serial 1)]]) serial standalone (entries idx))))

(println "\nAll demo checks passed")
