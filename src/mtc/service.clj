;; A small MTC CA + verification sidecar over ring-chez-adapter.
;; Run: JOLT_SKIP_MIN_VERSION=1 jolt -A:server run -m mtc.service
(ns mtc.service
  "An HTTP sidecar that issues one Merkle Tree Certificate for a demo client
  and verifies presented certificates (RFC 7).  Endpoints:

    GET  /health        -> ok
    GET  /checkpoint    -> {size, root} JSON
    GET  /client-cert   -> the standalone cert (PEM)
    GET  /client-key    -> the client private key (PKCS#8 PEM)
    POST /verify        -> body is the cert (PEM or DER); {valid, reason}
    GET  /auth          -> nginx auth_request: X-Client-Cert header (PEM)
    POST /ext_authz     -> envoy ext_authz HTTP CheckRequest JSON"
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
            [mtc.sig :as sig]))

(def ca-id [32473 1])
(def cn-oid [2 5 4 3])
(def ed25519-alg (der/encode [:seq [:oid [1 3 101 112]]]))
(def mtc-sig-alg (der/encode [:seq [:oid [1 3 6 1 5 5 7 6 67]]]))

;; --- CA setup ----------------------------------------------------------------

(defn setup-ca []
  (let [client-kp (sig/ed25519-key-pair)
        cosigner-kp (sig/ed25519-key-pair)
        spki (.getEncoded (:public client-kp))
        spki-hash (sha/digest spki)
        issuer (x/encode-trust-anchor-name ca-id)
        validity (x/encode-validity [:utc "240101000000Z"] [:utc "260101000000Z"])
        subject (x/encode-name [[[cn-oid [:utf8 "client.example.com"]]]])
        tbs {:version 2
             :issuer issuer
             :validity validity
             :subject subject
             :subject-public-key-algorithm ed25519-alg
             :subject-public-key-info-hash spki-hash}
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
        cosig (cos/sign (sig/ed25519-signer) (:private cosigner-kp) cst)
        mtc-proof {:extensions []
                   :start 0 :end 1
                   :inclusion-proof proof
                   :signatures [{:cosigner-id (cos/cosigner-id-bytes ca-id)
                                 :signature cosig}]}
        cert-der (der/encode
                   [:seq
                    [:raw (der/encode [:seq
                                       [:ctx 0 [:int 2]]
                                       [:int serial]
                                       [:raw mtc-sig-alg]
                                       [:raw issuer]
                                       [:raw validity]
                                       [:raw subject]
                                       [:raw spki]])]
                    [:raw mtc-sig-alg]
                    [:bitstring (cert/encode-mtc-proof mtc-proof)]])]
    {:log L
     :client-key (:private client-kp)
     :client-cert-der cert-der
     :config {:ca-id ca-id
              :trusted-subtrees []
              :cosigner-verifiers [{:cosigner-id ca-id
                                    :public-key (:public cosigner-kp)
                                    :verify-fn (sig/ed25519-verifier)}]
              :cosigner-policy (fn [ids] (some #{ca-id} ids))
              :revoked-ranges []}}))

;; --- PEM / URL helpers -------------------------------------------------------

(defn b64 [bytes] (.encodeToString (java.util.Base64/getEncoder) bytes))
(defn wrap64 [s] (str/join "\n" (re-seq #".{1,64}" s)))
(defn pem [label der] (str "-----BEGIN " label "-----\n" (wrap64 (b64 der)) "\n-----END " label "-----\n"))
(defn cert-pem [der] (pem "CERTIFICATE" der))
(defn key-pem [der] (pem "PRIVATE KEY" der))

(defn pem->der [s]
  (let [body (->> (str/split-lines s)
                  (remove #(str/starts-with? % "-----"))
                  (str/join ""))]
    (.decode (java.util.Base64/getDecoder) body)))

(defn url-decode [s]
  (let [sb (StringBuilder.)]
    (loop [i 0]
      (when (< i (count s))
        (let [c (.charAt s i)]
          (if (= c \%)
            (do (.append sb (char (Long/parseLong (subs s (+ i 1) (+ i 3)) 16)))
                (recur (+ i 3)))
            (do (.append sb c) (recur (inc i)))))))
    (.toString sb)))

(defn body-bytes
  "The request body as a byte array (or nil)."
  [req]
  (let [b (:body req)]
    (cond
      (nil? b) nil
      (string? b) (.getBytes b "UTF-8")
      :else (.readAllBytes b))))

(defn body-str [req]
  (let [b (body-bytes req)]
    (if b (String. b "UTF-8") "")))

(defn pem-bytes? [b]
  (and b (pos? (alength b))
       (= 45 (bit-and (aget b 0) 0xFF))
       (= 45 (bit-and (aget b 1) 0xFF))
       (= 45 (bit-and (aget b 2) 0xFF))))

;; --- handlers ----------------------------------------------------------------

(defn verify* [config cert-der]
  (try
    {:valid (rp/verify-certificate config cert-der)}
    (catch Throwable e {:valid false :reason (.getMessage e)})))

(defn json-resp [m]
  {:status 200 :headers {"Content-Type" "application/json"} :body (json/write-str m)})

(defn- route [state req]
  (let [path (:uri req)
        method (:request-method req)]
    (cond
      (= "/health" path)
      {:status 200 :body "ok"}

      (= "/checkpoint" path)
      (json-resp {:size (log/tree-size (:log state))
                  :root (apply str (map (fn [x] (format "%02x" (bit-and x 0xff)))
                                        (log/root-hash (:log state))))})

      (= "/client-cert" path)
      {:status 200 :headers {"Content-Type" "application/x-pem-file"}
       :body (cert-pem (:client-cert-der state))}

      (= "/client-key" path)
      {:status 200 :headers {"Content-Type" "application/x-pem-file"}
       :body (key-pem (.getEncoded (:client-key state)))}

      (and (= "/verify" path) (= :post method))
      (let [body (body-bytes req)
            der (if (pem-bytes? body) (pem->der (String. body "UTF-8")) body)]
        (json-resp (verify* (:config state) der)))

      (= "/auth" path)
      (let [cert (get-in req [:headers "x-client-cert"])
            der (when cert (pem->der (url-decode cert)))
            ok (and der (:valid (verify* (:config state) der)))]
        {:status (if ok 200 401) :body (if ok "ok" "unauthorized")})

      (str/starts-with? path "/ext_authz")
      (let [s (body-str req)
            j (try (json/read-str s) (catch Throwable _ {}))
            cert (or (get-in j ["attributes" "source" "certificate"])
                     (get-in j ["attributes" "request" "http" "headers" "x-mtc-cert"]))
            der (when cert (pem->der (url-decode cert)))
            ok (and der (:valid (verify* (:config state) der)))]
        (json-resp (if ok
                     {"allowed" true}
                     {"denied" {"status" {"code" 16}}})))

      :else {:status 404 :body (str "not found: " path " " method)})))

(defn handler [state]
  (fn [req]
    (try
      (route state req)
      (catch Throwable e
        {:status 500 :headers {"Content-Type" "text/plain"}
         :body (str "internal error: " (.getMessage e))}))))

(defn -main [& _]
  (let [state (setup-ca)]
    (println "MTC verification sidecar on :8080 (CA" (str/join "." ca-id) ")")
    (adapter/run-server (handler state) {:port 8080 :host "0.0.0.0"})
    (println "started")
    @(promise)))
