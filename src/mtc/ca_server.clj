;; A persistent, self-signing Merkle Tree CA + verifier service.
;; Run: MTC_DATA_DIR=/data JOLT_SKIP_MIN_VERSION=1 jolt -A:server run -m mtc.ca-server
(ns mtc.ca-server
  "A deployable MTC CA: issues standalone certificates on demand, persists its
  Ed25519 cosigner key and append-only issuance log, and verifies presented
  certificates. Self-consistent and self-signing (the CA cosigner signs its own
  subtrees).

  Endpoints:
    GET  /health /checkpoint /config
    POST /issue       {subject} -> {index, serial, cert, key}
    GET  /cert/{i} /key/{i}
    POST /verify GET /auth POST /ext_authz"
  (:require [clojure.data.json :as json]
            [clojure.string :as str]
            [ring-chez.adapter :as adapter]
            [mtc.der :as der]
            [mtc.x509 :as x]
            [mtc.entry :as entry]
            [mtc.log :as log]
            [mtc.certificate :as cert]
            [mtc.cosigner :as cos]
            [mtc.relying-party :as rp]
            [mtc.sha256 :as sha]
            [mtc.merkle :as m]
            [mtc.sig :as sig]
            [mtc.policy :as policy]
            [mtc.service :as svc]
            [jolt.http-client :as http]))

(def ca-id [32473 1])
(def cn-oid [2 5 4 3])
(def ed25519-alg (der/encode [:seq [:oid [1 3 101 112]]]))
(def mtc-sig-alg (der/encode [:seq [:oid [1 3 6 1 5 5 7 6 67]]]))
(def data-dir (or (System/getenv "MTC_DATA_DIR") "/data"))

(defn- path [& parts] (str data-dir "/" (str/join "/" parts)))
(defn- write-bytes [p bs] (let [o (java.io.FileOutputStream. p)] (.write o bs) (.close o)))
(defn- read-bytes [p] (.readAllBytes (java.io.FileInputStream. p)))

(defn- load-revoked []
  (try (get (json/read-str (String. (read-bytes (path "revoked.json")) "UTF-8")) "ranges" [])
       (catch Throwable _ [])))

(defn- save-revoked [ranges]
  (write-bytes (path "revoked.json") (.getBytes (json/write-str {"ranges" ranges}) "UTF-8")))

(defn- load-key-or-gen []
  (let [kp (try
             [(sig/parse-private-key "Ed25519" (read-bytes (path "ca-key.p8")))
              (sig/parse-public-key "Ed25519" (read-bytes (path "ca-pub.spki")))]
             (catch Throwable _ nil))]
    (or kp (let [k (sig/ed25519-key-pair)
                 priv (:private k) pub (:public k)]
             (write-bytes (path "ca-key.p8") (.getEncoded priv))
             (write-bytes (path "ca-pub.spki") (.getEncoded pub))
             [priv pub]))))

(defn- issuer-name [] (x/encode-trust-anchor-name ca-id))
(defn- validity [] (x/encode-validity [:utc "240101000000Z"] [:utc "260101000000Z"]))

(defn- tbs-map [subject spki]
  {:version 2
   :issuer (issuer-name)
   :validity (validity)
   :subject (x/encode-name [[[cn-oid [:utf8 subject]]]])
   :subject-public-key-algorithm ed25519-alg
   :subject-public-key-info-hash (sha/digest spki)})

(defn- log-entry-bytes [subject spki]
  (entry/encode-mtc-log-entry [] entry/tbs-cert-entry
                              (entry/encode-tbs-cert-log-entry-fields (tbs-map subject spki))))

(defn- build-cert [serial subject spki mtc-proof]
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

(def cosigner-urls
  (let [v (System/getenv "MTC_COSIGNERS")]
    (if (and v (not (str/blank? v)))
      (str/split v #",")
      [])))

(def quorum
  (let [v (System/getenv "MTC_QUORUM")]
    (if (and v (not (str/blank? v))) (Long/parseLong v) 1)))

(defn- http-get-json [url]
  (json/read-str (:body (http/get url {:as :string}))))

(defn- load-cosigners []
  (mapv (fn [url]
          {:url url
           :id (get (http-get-json (str url "/id")) "cosigner-id")
           :public-key (sig/parse-public-key "Ed25519"
                         (.decode (java.util.Base64/getDecoder)
                                  (get (http-get-json (str url "/public-key")) "public-key")))})
        cosigner-urls))

(defn- make-state []
  (let [[priv pub] (load-key-or-gen)
        L (log/load-log 1 (path "log.bin"))
        cosigners (load-cosigners)
        witness-ids (mapv :id cosigners)]
    (atom {:ca-key priv
           :ca-pub pub
           :log L
           :cosigners cosigners
           :witness-ids witness-ids
           :clients {}   ; index -> {:key priv :cert der}
           :revoked-ranges (load-revoked)
           :config {:ca-id ca-id
                    :trusted-subtrees []
                    :cosigner-verifiers (into [{:cosigner-id ca-id :public-key pub :verify-fn (sig/ed25519-verifier)}]
                                              (map (fn [c] {:cosigner-id (:id c) :public-key (:public-key c) :verify-fn (sig/ed25519-verifier)}) cosigners))
                    :cosigner-policy (if (seq witness-ids)
                                       (policy/ca-and-n-of ca-id witness-ids (min quorum (count witness-ids)))
                                       (policy/any-of [ca-id]))
                    :revoked-ranges []}})))

(defn- issue! [state subject]
  (let [kp (sig/ed25519-key-pair)
        spki (.getEncoded (:public kp))
        entry (log-entry-bytes subject spki)
        new-log (log/append! (:log @state) entry)
        index (dec (log/tree-size new-log))
        serial (cert/serial-number 1 index)]
    ;; Commit the entry before cosigning, so witnesses sync to the new checkpoint.
    (swap! state assoc :log new-log)
    (log/save-log new-log (path "log.bin"))
    (let [proof (log/inclusion-proof new-log 0 (log/tree-size new-log) index)
          cst {:cosigner-name (cos/trust-anchor-name ca-id)
               :timestamp 0
               :log-origin (cos/trust-anchor-name (rp/log-id ca-id 1))
               :start 0 :end (log/tree-size new-log)
               :subtree-hash (log/root-hash new-log)}
          cosig (cos/sign (sig/ed25519-signer) (:ca-key @state) cst)
          witness-sigs
          (mapv (fn [c]
                  (let [wcst {:cosigner-name (cos/trust-anchor-name (:id c))
                              :timestamp 0
                              :log-origin (cos/trust-anchor-name (rp/log-id ca-id 1))
                              :start 0 :end (log/tree-size new-log)
                              :subtree-hash (log/root-hash new-log)}
                        raw (:body (http/post (str (:url c) "/cosign")
                                               {:body (json/write-str {"cosigned-subtree" (svc/b64 (cos/encode-cosigned-subtree wcst))})
                                                :content-type :json :as :string
                                                :throw-exceptions false}))
                        resp (json/read-str raw)
                        sig (get resp "signature")]
                    (if sig
                      {:cosigner-id (cos/cosigner-id-bytes (:id c))
                       :signature (.decode (java.util.Base64/getDecoder) sig)}
                      (throw (ex-info (str "cosigner " (:id c) " refused: " raw) {})))))
                (:cosigners @state))
          mtc-proof {:extensions [] :start 0 :end (log/tree-size new-log)
                     :inclusion-proof proof
                     :signatures (into [{:cosigner-id (cos/cosigner-id-bytes ca-id) :signature cosig}] witness-sigs)}
          der (build-cert serial subject spki mtc-proof)]
      (swap! state assoc :clients (assoc (:clients @state) index {:key (:private kp) :cert der}))
      (write-bytes (path (str "client-" index ".p8")) (.getEncoded (:private kp)))
      {:index index :serial serial
       :root (svc/b64 (log/root-hash new-log))})))

(defn- handler [state]
  (fn [req]
    (try
      (let [path (:uri req)
            method (:request-method req)
            cfg (assoc (:config @state) :revoked-ranges (:revoked-ranges @state))]
        (cond
          (= "/health" path) {:status 200 :body "ok"}

          (= "/checkpoint" path)
          (svc/json-resp {:size (log/tree-size (:log @state))
                          :root (apply str (map (fn [x] (format "%02x" (bit-and x 0xff)))
                                               (log/root-hash (:log @state))))})

          (= "/config" path)
          (svc/json-resp {:ca-id ca-id
                          :cosigner-public-key (svc/b64 (.getEncoded (:ca-pub @state)))
                          :root (apply str (map (fn [x] (format "%02x" (bit-and x 0xff)))
                                               (log/root-hash (:log @state))))})

          (and (= "/issue" path) (= :post method))
          (let [j (try (json/read-str (svc/body-str req)) (catch Throwable _ {}))
                subject (or (get j "subject") "client.example.com")]
            (svc/json-resp (issue! state subject)))

          (and (= "/revoke" path) (= :post method))
          (let [j (json/read-str (svc/body-str req))
                s (long (get j "start"))
                e (long (get j "end"))]
            (swap! state update :revoked-ranges conj [s e])
            (save-revoked (:revoked-ranges @state))
            (svc/json-resp {"revoked-ranges" (:revoked-ranges @state)}))

          (str/starts-with? path "/entries/")
          (let [from (Long/parseLong (subs path 9))
                entries (vec (:entries (:log @state)))]
            (svc/json-resp (mapv svc/b64 (subvec entries from))))

          (str/starts-with? path "/cert/")
          (let [i (Long/parseLong (subs path 6))
                c (get-in @state [:clients i])]
            (if c {:status 200 :headers {"Content-Type" "application/x-pem-file"} :body (svc/cert-pem (:cert c))}
                  {:status 404 :body "no such cert"}))

          (str/starts-with? path "/key/")
          (let [i (Long/parseLong (subs path 5))
                c (get-in @state [:clients i])]
            (if c {:status 200 :headers {"Content-Type" "application/x-pem-file"} :body (svc/key-pem (.getEncoded (:key c)))}
                  {:status 404 :body "no such key"}))

          (and (= "/verify" path) (= :post method))
          (let [body (svc/body-bytes req)
                der (if (svc/pem-bytes? body) (svc/pem->der (String. body "UTF-8")) body)]
            (svc/json-resp (svc/verify* cfg der)))

          (= "/auth" path)
          (let [cert (get-in req [:headers "x-client-cert"])
                der (when cert (svc/pem->der (svc/url-decode cert)))
                ok (and der (:valid (svc/verify* cfg der)))]
            {:status (if ok 200 401) :body (if ok "ok" "unauthorized")})

          (str/starts-with? path "/ext_authz")
          (let [j (try (json/read-str (svc/body-str req)) (catch Throwable _ {}))
                cert (or (get-in j ["attributes" "source" "certificate"])
                         (get-in j ["attributes" "request" "http" "headers" "x-mtc-cert"]))
                der (when cert (svc/pem->der (svc/url-decode cert)))
                ok (and der (:valid (svc/verify* cfg der)))]
            (if ok (svc/json-resp {"allowed" true})
                    {:status 401 :headers {"Content-Type" "application/json"}
                     :body (json/write-str {"denied" {"status" {"code" 401}}})}))

          :else {:status 404 :body (str "not found: " path " " method)}))
      (catch Throwable e {:status 500 :body (str "internal error: " (.getMessage e))}))))

(defn -main [& _]
  (let [st (make-state)]
    (println "MTC CA + verifier on :8080 (CA" (str/join "." ca-id) ") data-dir:" data-dir)
    (adapter/run-server (handler st) {:port 8080 :host "0.0.0.0"})
    (println "started")
    @(promise)))
