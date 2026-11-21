;; Standalone MTC CA + verifier entrypoint, for `jolt build -m mtc.cli`.
(ns mtc.cli
  "A runnable Merkle Tree Certificate CLI: runs a demo CA, issues a standalone
  certificate for an entry, verifies it through mtc.relying-party, and writes
  the DER certificate to cert.der.  Usage: mtc.cli [entry-index]"
  (:require [clojure.string :as str]
            [mtc.der :as der]
            [mtc.x509 :as x]
            [mtc.entry :as entry]
            [mtc.log :as log]
            [mtc.certificate :as cert]
            [mtc.cosigner :as cos]
            [mtc.relying-party :as rp]
            [mtc.sha256 :as sha]
            [mtc.merkle :as m]))

(defn hex [b] (apply str (map (fn [x] (format "%02x" (bit-and x 0xff))) b)))

(def cn-oid [2 5 4 3])
(def ca-id [32473 1])
(def issuer-name (x/encode-trust-anchor-name ca-id))
(def validity (x/encode-validity [:utc "240101000000Z"] [:utc "260101000000Z"]))
(def spki-alg (der/encode [:seq [:oid [1 3 101 112]]]))  ; Ed25519, params absent
(def demo-pubkey (byte-array (map unchecked-byte (range 32))))
(def spki (der/encode [:seq [:raw spki-alg] [:bitstring demo-pubkey]]))
(def spki-hash (sha/digest spki))
(def mtc-sig-alg (der/encode [:seq [:oid [1 3 6 1 5 5 7 6 67]]]))

(defn subject-name [i]
  (x/encode-name [[[cn-oid [:utf8 (str "service-" i ".example.com")]]]]))

(defn tbs-map [i]
  {:version 2
   :issuer issuer-name
   :validity validity
   :subject (subject-name i)
   :subject-public-key-algorithm spki-alg
   :subject-public-key-info-hash spki-hash})

(defn log-entry [i]
  (entry/encode-mtc-log-entry [] entry/tbs-cert-entry
                              (entry/encode-tbs-cert-log-entry-fields (tbs-map i))))

;; Deterministic demo cosigner (a real algorithm plugs in via mtc.sig + :crypto).
(def ca-key (.getBytes "demo-ca-key" "UTF-8"))
(defn sign [k msg] (sha/digest (byte-array (concat (seq k) (seq msg)))))
(defn verify [k msg sig] (m/bytes= sig (sign k msg)))

(defn build-cert [serial subject mtc-proof]
  (der/encode
    [:seq
     [:raw (der/encode [:seq
                        [:ctx 0 [:int 2]]
                        [:int serial]
                        [:raw mtc-sig-alg]
                        [:raw issuer-name]
                        [:raw validity]
                        [:raw subject]
                        [:raw spki]])]
     [:raw mtc-sig-alg]
     [:bitstring (cert/encode-mtc-proof mtc-proof)]]))

(defn -main [& args]
  (let [idx (if (seq args) (Long/parseLong (first args)) 5)
        entries (mapv log-entry (range 20))
        L (reduce log/append! (log/new-log 1) entries)
        serial (cert/serial-number 1 idx)
        proof (log/inclusion-proof L 0 20 idx)
        cst {:cosigner-name (cos/trust-anchor-name ca-id)
             :timestamp 0
             :log-origin (cos/trust-anchor-name (rp/log-id ca-id 1))
             :start 0 :end 20
             :subtree-hash (log/root-hash L)}
        sig (cos/sign sign ca-key cst)
        mtc-proof {:extensions []
                   :start 0 :end 20
                   :inclusion-proof proof
                   :signatures [{:cosigner-id (cos/cosigner-id-bytes ca-id)
                                 :signature sig}]}
        cert-der (build-cert serial (subject-name idx) mtc-proof)
        config {:ca-id ca-id
                :trusted-subtrees []
                :cosigner-verifiers [{:cosigner-id ca-id :public-key ca-key :verify-fn verify}]
                :cosigner-policy (fn [ids] (some #{ca-id} ids))
                :revoked-ranges []}
        ok (rp/verify-certificate config cert-der)]
    (println "== Merkle Tree Certificate (standalone) ==")
    (println "CA ID:                " (str/join "." ca-id))
    (println "issuance log:         log 1, " (log/tree-size L) " entries")
    (println "log root hash:        " (hex (log/root-hash L)))
    (println "entry index:          " idx)
    (println "serial number:        " serial)
    (println "inclusion proof:      " (count proof) " hashes")
    (println "cosignature:          " (hex sig))
    (println "certificate (DER hex): " (hex cert-der))
    (println "verify-certificate:   " ok)
    (let [f (java.io.FileOutputStream. "cert.der")]
      (.write f cert-der)
      (.close f))
    (println "wrote cert.der (" (alength cert-der) " bytes)")
    (when-not ok (System/exit 1))
    (println "OK")))
