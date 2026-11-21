;; A standalone cosigner (witness/mirror) service: signs subtrees the CA submits.
;; Run: MTC_DATA_DIR=/data MTC_COSIGNER_ID=32473.1.101 JOLT_SKIP_MIN_VERSION=1 jolt -A:server run -m mtc.cosigner-server
(ns mtc.cosigner-server
  "A cosigner instance with its own Ed25519 identity. The CA submits an encoded
  CosignedSubtree; this service verifies the cosigner_name matches its ID and
  returns the cosignature. Endpoints: GET /health /id /public-key, POST /cosign."
  (:require [clojure.data.json :as json]
            [clojure.string :as str]
            [ring-chez.adapter :as adapter]
            [mtc.cosigner :as cos]
            [mtc.sig :as sig]
            [mtc.service :as svc]))

(def data-dir (or (System/getenv "MTC_DATA_DIR") "/data"))

(defn- parse-arcs [s] (mapv #(Long/parseLong %) (str/split s #"\.")))

(def cosigner-id
  (if-let [v (System/getenv "MTC_COSIGNER_ID")]
    (parse-arcs v)
    [32473 1 101]))

(defn- path [& parts] (str data-dir "/" (str/join "/" parts)))
(defn- write-bytes [p bs] (let [o (java.io.FileOutputStream. p)] (.write o bs) (.close o)))
(defn- read-bytes [p] (.readAllBytes (java.io.FileInputStream. p)))

(defn- load-key-or-gen []
  (let [k (try
            [(sig/parse-private-key "Ed25519" (read-bytes (path "cosigner-key.p8")))
             (sig/parse-public-key "Ed25519" (read-bytes (path "cosigner-pub.spki")))]
            (catch Throwable _ nil))]
    (or k (let [kp (sig/ed25519-key-pair)
                priv (:private kp) pub (:public kp)]
            (write-bytes (path "cosigner-key.p8") (.getEncoded priv))
            (write-bytes (path "cosigner-pub.spki") (.getEncoded pub))
            [priv pub]))))

(defn- b64 [bs] (.encodeToString (java.util.Base64/getEncoder) bs))
(defn- unb64 [s] (.decode (java.util.Base64/getDecoder) s))

(defn- handler [priv pub]
  (fn [req]
    (try
      (let [path (:uri req)
            method (:request-method req)]
        (cond
          (= "/health" path) {:status 200 :body "ok"}

          (= "/id" path) (svc/json-resp {"cosigner-id" cosigner-id})

          (= "/public-key" path)
          (svc/json-resp {"public-key" (b64 (.getEncoded pub))})

          (and (= "/cosign" path) (= :post method))
          (let [j (json/read-str (svc/body-str req))
                cst (cos/decode-cosigned-subtree (unb64 (get j "cosigned-subtree")))
                _ (when-not (= (cos/trust-anchor-name cosigner-id) (:cosigner-name cst))
                    (throw (ex-info "cosigner_name mismatch" {:expected (cos/trust-anchor-name cosigner-id) :got (:cosigner-name cst)})))]
            (svc/json-resp {"signature" (b64 (cos/sign (sig/ed25519-signer) priv cst))}))

          :else {:status 404 :body (str "not found: " path)}))
      (catch Throwable e {:status 500 :body (str "internal error: " (.getMessage e))}))))

(defn -main [& _]
  (let [[priv pub] (load-key-or-gen)]
    (println "MTC cosigner on :8080, id" (str/join "." cosigner-id))
    (adapter/run-server (handler priv pub) {:port 8080 :host "0.0.0.0"})
    (println "started")
    @(promise)))
