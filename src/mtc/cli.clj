;; A small MTC CLI: issue a self-signed certificate or run the demo.
;; Build: jolt -A:crypto build -m mtc.cli -o mtc-cli
(ns mtc.cli
  "Create and verify Merkle Tree Certificates from the command line.

  Usage:
    mtc.cli issue <subject> [out-prefix]
        Generate an Ed25519 keypair, self-sign a standalone MTC for the
        subject, write <prefix>.crt and <prefix>.key (PEM), and self-verify.
        Default prefix is the subject with non-alphanumerics replaced by '_'.

    mtc.cli demo [index]
        Run the fixed 20-entry demo (issue for an index, verify, write cert.der)."
  (:require [clojure.string :as str]
            [mtc.der :as der]
            [mtc.x509 :as x]
            [mtc.entry :as entry]
            [mtc.log :as log]
            [mtc.certificate :as cert]
            [mtc.cosigner :as cos]
            [mtc.relying-party :as rp]
            [mtc.sha256 :as sha]
            [mtc.merkle :as m]
            [mtc.sig :as sig]))

(def ca-id [32473 1])
(def cn-oid [2 5 4 3])
(def ed25519-alg (der/encode [:seq [:oid [1 3 101 112]]]))
(def mtc-sig-alg (der/encode [:seq [:oid [1 3 6 1 5 5 7 6 67]]]))

(defn hex [b] (apply str (map (fn [x] (format "%02x" (bit-and x 0xff))) b)))
(defn b64 [b] (.encodeToString (java.util.Base64/getEncoder) b))
(defn wrap64 [s] (str/join "\n" (re-seq #".{1,64}" s)))
(defn pem [label der] (str "-----BEGIN " label "-----\n" (wrap64 (b64 der)) "\n-----END " label "-----\n"))

(defn- issuer-name [] (x/encode-trust-anchor-name ca-id))
(defn- validity [] (x/encode-validity [:utc "240101000000Z"] [:utc "260101000000Z"]))

(defn- build-cert [subject spki serial mtc-proof]
  (der/encode
    [:seq
     [:raw (der/encode [:seq
                        [:ctx 0 [:int 2]]
                        [:int serial]
                        [:raw mtc-sig-alg]
                        [:raw (issuer-name)]
                        [:raw (validity)]
                        [:raw (x/encode-name [[[cn-oid [:utf8 subject]]]])]
                        [:raw spki]])]
     [:raw mtc-sig-alg]
     [:bitstring (cert/encode-mtc-proof mtc-proof)]]))

(defn issue!
  "Issue a self-signed standalone MTC for `subject`. Returns
  {:cert der :key pkcs8 :serial n}."
  [subject]
  (let [client-kp (sig/ed25519-key-pair)
        ca-kp (sig/ed25519-key-pair)
        spki (.getEncoded (:public client-kp))
        tbs {:version 2
             :issuer (issuer-name)
             :validity (validity)
             :subject (x/encode-name [[[cn-oid [:utf8 subject]]]])
             :subject-public-key-algorithm ed25519-alg
             :subject-public-key-info-hash (sha/digest spki)}
        entry (entry/encode-mtc-log-entry [] entry/tbs-cert-entry
                                          (entry/encode-tbs-cert-log-entry-fields tbs))
        L (log/append! (log/new-log 1) entry)
        serial (cert/serial-number 1 0)
        proof (log/inclusion-proof L 0 1 0)
        cst {:cosigner-name (cos/trust-anchor-name ca-id)
             :timestamp 0
             :log-origin (cos/trust-anchor-name (rp/log-id ca-id 1))
             :start 0 :end 1
             :subtree-hash (log/root-hash L)}
        cosig (cos/sign (sig/ed25519-signer) (:private ca-kp) cst)
        mtc-proof {:extensions [] :start 0 :end 1 :inclusion-proof proof
                   :signatures [{:cosigner-id (cos/cosigner-id-bytes ca-id) :signature cosig}]}
        cert-der (build-cert subject spki serial mtc-proof)
        config {:ca-id ca-id :trusted-subtrees []
                :cosigner-verifiers [{:cosigner-id ca-id :public-key (:public ca-kp) :verify-fn (sig/ed25519-verifier)}]
                :cosigner-policy (fn [ids] (some #{ca-id} ids))
                :revoked-ranges []}]
    {:cert cert-der
     :key (.getEncoded (:private client-kp))
     :serial serial
     :valid (rp/verify-certificate config cert-der)}))

(defn- issue-command [args]
  (let [subject (or (first args) "localhost")
        prefix (or (second args) (str/replace subject #"[^a-zA-Z0-9.-]" "_"))
        r (issue! subject)
        cert-file (str prefix ".crt")
        key-file (str prefix ".key")]
    (spit cert-file (pem "CERTIFICATE" (:cert r)))
    (spit key-file (pem "PRIVATE KEY" (:key r)))
    (println "issued self-signed MTC for" subject)
    (println "  cert:  " cert-file)
    (println "  key:   " key-file)
    (println "  serial:" (:serial r))
    (println "  self-verified:" (:valid r))))

(defn- demo [& args]
  (let [idx (if (seq args) (Long/parseLong (first args)) 5)
        entries (mapv (fn [i] (byte-array [i])) (range 20))
        L (reduce log/append! (log/new-log 1) entries)
        root (log/root-hash L)
        serial (cert/serial-number 1 idx)
        proof (log/inclusion-proof L 0 20 idx)]
    (println "== MTC demo (fixed 20-entry log) ==")
    (println "root:  " (hex root))
    (println "index: " idx " serial: " serial " proof: " (count proof) " hashes")))

(defn- usage []
  (println "usage:")
  (println "  mtc.cli issue <subject> [out-prefix]")
  (println "  mtc.cli demo [index]"))

(defn -main [& args]
  (case (first args)
    "issue" (issue-command (rest args))
    "demo" (demo (rest args))
    (usage)))
