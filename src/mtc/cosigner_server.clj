;; A standalone cosigner (witness/mirror) service.
;; Run: MTC_DATA_DIR=/data MTC_COSIGNER_ID=32473.1.101 MTC_CA_URL=http://ca:8080 JOLT_SKIP_MIN_VERSION=1 jolt -A:server run -m mtc.cosigner-server
(ns mtc.cosigner-server
  "A cosigner with its own Ed25519 identity that follows the CA's issuance log.
  Before signing a submitted CosignedSubtree it advances its own log view to
  the CA's checkpoint, verifies the view's root matches the CA's root (fork
  detection), and verifies the submitted subtree hash matches its own view.

  Endpoints: GET /health /id /public-key /checkpoint, POST /cosign."
  (:require [clojure.data.json :as json]
            [clojure.string :as str]
            [ring-chez.adapter :as adapter]
            [mtc.cosigner :as cos]
            [mtc.log :as log]
            [mtc.merkle :as m]
            [mtc.sig :as sig]
            [mtc.service :as svc]
            [jolt.http-client :as http]))

(def data-dir (or (System/getenv "MTC_DATA_DIR") "/data"))
(def ca-url (System/getenv "MTC_CA_URL"))

(defn- parse-arcs [s] (mapv #(Long/parseLong %) (str/split s #"\.")))
(def cosigner-id
  (if-let [v (System/getenv "MTC_COSIGNER_ID")]
    (parse-arcs v)
    [32473 1 101]))

(defn- path [& parts] (str data-dir "/" (str/join "/" parts)))
(defn- write-bytes [p bs] (let [o (java.io.FileOutputStream. p)] (.write o bs) (.close o)))
(defn- read-bytes [p] (.readAllBytes (java.io.FileInputStream. p)))
(defn- b64 [bs] (.encodeToString (java.util.Base64/getEncoder) bs))
(defn- unb64 [s] (.decode (java.util.Base64/getDecoder) s))
(defn- hex [bs] (apply str (map (fn [x] (format "%02x" (bit-and x 0xff))) bs)))

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

(defn- make-state []
  (let [[priv pub] (load-key-or-gen)
        L (log/load-log 1 (path "witness-log.bin"))]
    (atom {:key priv :pub pub :log L})))

(defn- sync-log!
  "Advance the witness's log to the CA's checkpoint and reject a fork."
  [state]
  (when-not ca-url
    (throw (ex-info "MTC_CA_URL is not set" {})))
  (let [ckpt (json/read-str (:body (http/get (str ca-url "/checkpoint") {:as :string})))
        ca-size (long (get ckpt "size"))
        ca-root (get ckpt "root")
        my-size (log/tree-size (:log @state))]
    (when (> ca-size my-size)
      (let [b64s (json/read-str (:body (http/get (str ca-url "/entries/" my-size) {:as :string})))
            new-log (reduce (fn [l s] (log/append! l (unb64 s))) (:log @state) b64s)]
        (swap! state assoc :log new-log)
        (log/save-log new-log (path "witness-log.bin"))))
    (let [my-root (hex (log/root-hash (:log @state)))]
      (when-not (= ca-root my-root)
        (throw (ex-info "CA log fork detected" {:ca-root ca-root :witness-root my-root}))))))

(defn- handler [state priv pub]
  (fn [req]
    (try
      (let [path (:uri req)
            method (:request-method req)]
        (cond
          (= "/health" path) {:status 200 :body "ok"}

          (= "/id" path) (svc/json-resp {"cosigner-id" cosigner-id})

          (= "/public-key" path) (svc/json-resp {"public-key" (b64 (.getEncoded pub))})

          (= "/checkpoint" path)
          (svc/json-resp {"size" (log/tree-size (:log @state))
                          "root" (hex (log/root-hash (:log @state)))})

          (and (= "/cosign" path) (= :post method))
          (let [j (json/read-str (svc/body-str req))
                cst (cos/decode-cosigned-subtree (unb64 (get j "cosigned-subtree")))
                _ (when-not (= (cos/trust-anchor-name cosigner-id) (:cosigner-name cst))
                    (throw (ex-info "cosigner_name mismatch"
                                    {:expected (cos/trust-anchor-name cosigner-id)
                                     :got (:cosigner-name cst)})))
                _ (sync-log! state)
                start (:start cst) end (:end cst)
                _ (when (> end (log/tree-size (:log @state)))
                    (throw (ex-info "subtree extends beyond witness view"
                                    {:end end :view (log/tree-size (:log @state))})))
                expected (m/mth (log/node-table (:log @state)) start end)
                _ (when-not (m/bytes= expected (:subtree-hash cst))
                    (throw (ex-info "subtree hash mismatch" {:start start :end end})))]
            (svc/json-resp {"signature" (b64 (cos/sign (sig/ed25519-signer) priv cst))}))

          :else {:status 404 :body (str "not found: " path)}))
      (catch Throwable e {:status 500 :headers {"Content-Type" "application/json"}
                          :body (json/write-str {"error" (.getMessage e)})}))))

(defn -main [& _]
  (let [state (make-state)
        priv (:key @state) pub (:pub @state)]
    (println "MTC witness cosigner on :8080, id" (str/join "." cosigner-id) "ca" ca-url)
    (adapter/run-server (handler state priv pub) {:port 8080 :host "0.0.0.0"})
    (println "started")
    @(promise)))
