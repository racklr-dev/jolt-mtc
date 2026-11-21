;; MTCLogEntry + TBSCertificateLogEntry round-trip tests.
;; Run: cd mtc && jolt run test/mtc/entry_test.clj
(ns mtc.test.entry
  (:require [jolt.der :as der]
            [mtc.entry :as e]
            [jolt.merkle :as m]))

(defn hex [b] (apply str (map (fn [x] (format "%02x" (bit-and x 0xff))) b)))

(defn check [label expected got]
  (if (= expected got)
    (println (str "PASS " label))
    (do (println (str "FAIL " label)) (println (str "  expected " (pr-str expected))) (println (str "  got      " (pr-str got))) (System/exit 1))))

;; --- MTCLogEntry ------------------------------------------------------------
;; type is a 2-byte enum (RFC 5.2.1: values up to 2^16-1)
(check "null entry wire" "00000000" (hex (e/encode-mtc-log-entry [] 0 nil)))
(check "tbs entry wire" "00000001" (hex (e/encode-mtc-log-entry [] 1 nil)))

(let [ext [[1 (.getBytes "aa" "UTF-8")] [300 (.getBytes "bb" "UTF-8")]]
      payload (.getBytes "tbs-bytes" "UTF-8")
      enc (e/encode-mtc-log-entry ext e/tbs-cert-entry payload)
      dec (e/decode-mtc-log-entry enc)]
  (check "mtc-log-entry type" e/tbs-cert-entry (:type dec))
  (check "mtc-log-entry payload" true (m/bytes= payload (:payload dec)))
  (check "mtc-log-entry ext count" 2 (count (:extensions dec)))
  (check "mtc-log-entry ext[0] type" 1 (first (first (:extensions dec))))
  (check "mtc-log-entry ext[0] data" true (m/bytes= (.getBytes "aa" "UTF-8") (second (first (:extensions dec)))))
  (check "mtc-log-entry ext[1] type" 300 (first (second (:extensions dec))))
  (check "mtc-log-entry ext[1] data" true (m/bytes= (.getBytes "bb" "UTF-8") (second (second (:extensions dec))))))

;; --- TBSCertificateLogEntry -------------------------------------------------
(let [issuer (der/encode [:seq [:int 1]])
      validity (der/encode [:seq [:int 2]])
      subject (der/encode [:seq [:int 3]])
      spki-alg (der/encode [:seq [:oid [1 2 840 113549 1 1 1]] [:null]])
      spki-hash (.getBytes "0123456789abcdef0123456789abcdef" "UTF-8")
      m {:issuer issuer
         :validity validity
         :subject subject
         :subject-public-key-algorithm spki-alg
         :subject-public-key-info-hash spki-hash}
      enc (e/encode-tbs-cert-log-entry m)
      dec (e/decode-tbs-cert-log-entry enc)]
  (check "tbs version default nil" nil (:version dec))
  (check "tbs issuer blob" true (m/bytes= issuer (:issuer dec)))
  (check "tbs validity blob" true (m/bytes= validity (:validity dec)))
  (check "tbs subject blob" true (m/bytes= subject (:subject dec)))
  (check "tbs spki-alg blob" true (m/bytes= spki-alg (:subject-public-key-algorithm dec)))
  (check "tbs spki-hash" true (m/bytes= spki-hash (:subject-public-key-info-hash dec)))
  ;; re-encode from the decoded map reproduces the same bytes
  (check "tbs re-encode stable" (hex enc) (hex (e/encode-tbs-cert-log-entry dec))))

;; --- with version, unique ids and extensions ---------------------------------
(let [issuer (der/encode [:seq [:int 1]])
      validity (der/encode [:seq [:int 2]])
      subject (der/encode [:seq [:int 3]])
      spki-alg (der/encode [:seq [:oid [1 2 840 113549 1 1 1]] [:null]])
      spki-hash (.getBytes "0123456789abcdef0123456789abcdef" "UTF-8")
      iuid (.getBytes "iuid" "UTF-8")
      suid (.getBytes "suid" "UTF-8")
      exts (der/encode [:seq [:int 99]])
      m {:version 2
         :issuer issuer
         :validity validity
         :subject subject
         :subject-public-key-algorithm spki-alg
         :subject-public-key-info-hash spki-hash
         :issuer-unique-id iuid
         :subject-unique-id suid
         :extensions exts}
      enc (e/encode-tbs-cert-log-entry m)
      dec (e/decode-tbs-cert-log-entry enc)]
  (check "tbs version v3" 2 (:version dec))
  (check "tbs issuer-unique-id" true (m/bytes= iuid (:issuer-unique-id dec)))
  (check "tbs subject-unique-id" true (m/bytes= suid (:subject-unique-id dec)))
  (check "tbs extensions blob" true (m/bytes= exts (:extensions dec)))
  (check "tbs full re-encode stable" (hex enc) (hex (e/encode-tbs-cert-log-entry dec))))

(println "All entry tests passed")
