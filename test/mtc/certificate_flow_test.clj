;; End-to-end: build a full DER X.509 Certificate carrying an MTCProof in its
;; signatureValue, then verify it through mtc.relying-party/verify-certificate.
;; Run: cd mtc && jolt run test/mtc/certificate_flow_test.clj
(ns mtc.test.certificate-flow
  (:require [jolt.der :as der]
            [jolt.x509 :as x]
            [mtc.tbs :as tbs]
            [mtc.entry :as entry]
            [mtc.log :as log]
            [mtc.certificate :as cert]
            [mtc.cosigner :as cos]
            [mtc.relying-party :as rp]
            [jolt.sha256 :as sha]
            [jolt.merkle :as m]))

(defn check [label expected got]
  (if (= expected got)
    (println (str "PASS " label))
    (do (println (str "FAIL " label)) (println (str "  expected " (pr-str expected))) (println (str "  got      " (pr-str got))) (System/exit 1))))

(def cn-oid [2 5 4 3])
(def issuer-name (x/encode-trust-anchor-name [32473 1]))
(def validity (x/encode-validity [:utc "240101000000Z"] [:utc "260101000000Z"]))
(def spki-alg (x/encode-alg-id [1 2 840 113549 1 1 1] nil))
(def spki (der/encode [:seq [:raw spki-alg] [:bitstring (.getBytes "subject-public-key" "UTF-8")]]))
(def spki-hash (sha/digest spki))
(def mtc-sig-alg (der/encode [:seq [:oid [1 3 6 1 5 5 7 6 67]]]))  ; id-alg-mtcProof, params omitted

(defn subject-name [i]
  (x/encode-name [[[cn-oid [:utf8 (str "service-" i ".example.com")]]]]))

(defn tbs-map [i]
  {:version 2
   :issuer issuer-name
   :validity validity
   :subject (subject-name i)
   :subject-public-key-algorithm spki-alg
   :subject-public-key-info-hash spki-hash})

;; CA: log of 20 entries
(def entries (mapv (fn [i]
                     (entry/encode-mtc-log-entry [] entry/tbs-cert-entry
                                                 (entry/encode-tbs-cert-log-entry-fields (tbs-map i))))
                   (range 20)))
(def L (reduce log/append! (log/new-log 1) entries))

;; dummy cosigner
(def cosigner-arcs [32473 1])
(def ca-key (.getBytes "ca-key" "UTF-8"))
(defn sign [k msg] (sha/digest (byte-array (concat (seq k) (seq msg)))))
(defn verify [k msg sig] (m/bytes= sig (sign k msg)))
(def config {:ca-id cosigner-arcs
             :trusted-subtrees []
             :cosigner-verifiers [{:cosigner-id cosigner-arcs :public-key ca-key :verify-fn verify}]
             :cosigner-policy (fn [ids] (some #{cosigner-arcs} ids))
             :revoked-ranges []})

(def idx 5)
(def serial (cert/serial-number 1 idx))
(def proof (log/inclusion-proof L 0 20 idx))
(def cst {:cosigner-name (cos/trust-anchor-name cosigner-arcs)
          :timestamp 0
          :log-origin (cos/trust-anchor-name (rp/log-id cosigner-arcs 1))
          :start 0 :end 20
          :subtree-hash (log/root-hash L)})
(def sig (cos/sign sign ca-key cst))
(def mtc-proof {:extensions []
                :start 0 :end 20
                :inclusion-proof proof
                :signatures [{:cosigner-id (cos/cosigner-id-bytes cosigner-arcs) :signature sig}]})

(defn build-cert [serial subject]
  (der/encode
    [:seq
     [:raw (der/encode [:seq
                        [:ctx 0 [:int 2]]      ; version v3
                        [:int serial]
                        [:raw mtc-sig-alg]     ; signature = id-alg-mtcProof
                        [:raw issuer-name]
                        [:raw validity]
                        [:raw subject]
                        [:raw spki]])]
     [:raw mtc-sig-alg]
     [:bitstring (cert/encode-mtc-proof mtc-proof)]]))

(def cert-der (build-cert serial (subject-name idx)))

(check "verify full certificate" true (rp/verify-certificate config cert-der))

;; tampered serial (points at a different index) fails
(check "tampered serial rejected" false (rp/verify-certificate config (build-cert (cert/serial-number 1 7) (subject-name idx))))

;; tampered subject (entry hash changes) fails
(check "tampered subject rejected" false (rp/verify-certificate config (build-cert serial (subject-name 9))))

;; verify the reconstructed entry hash equals the direct log entry hash
(let [tbs (x/parse-tbs-certificate (:tbs-certificate (x/parse-certificate cert-der)))
      reconstructed (tbs/mtc-log-entry-bytes-from-tbs sha/digest tbs [])]
  (check "reconstructed entry == log entry" true (m/bytes= (entries idx) reconstructed)))

;; wrong signatureAlgorithm (not id-alg-mtcProof) rejected
(let [wrong (x/encode-alg-id [1 2 840 113549 1 1 1] nil)
      bad-cert (der/encode
                 [:seq
                  [:raw (der/encode [:seq [:ctx 0 [:int 2]] [:int serial] [:raw wrong] [:raw issuer-name] [:raw validity] [:raw (subject-name idx)] [:raw spki]])]
                  [:raw wrong]
                  [:bitstring (cert/encode-mtc-proof mtc-proof)]])]
  (check "wrong signatureAlgorithm rejected" false (rp/verify-certificate config bad-cert)))

(println "All certificate-flow tests passed")
