;; MTCProof encode/decode, serialNumber, cosignature ordering.
;; Run: cd mtc && jolt run test/mtc/certificate_test.clj
(ns mtc.test.certificate
  (:require [mtc.certificate :as cert]
            [jolt.merkle :as m]))

(defn hex [b] (apply str (map (fn [x] (format "%02x" (bit-and x 0xff))) b)))

(defn check [label expected got]
  (if (= expected got)
    (println (str "PASS " label))
    (do (println (str "FAIL " label)) (println (str "  expected " (pr-str expected))) (println (str "  got      " (pr-str got))) (System/exit 1))))

(check "serial 1 0" 281474976710656 (cert/serial-number 1 0))
(check "serial 1 5" 281474976710661 (cert/serial-number 1 5))
(check "serial 2 7" 562949953421319 (cert/serial-number 2 7))

(let [h1 (byte-array (map unchecked-byte (range 32)))
      h2 (byte-array (map unchecked-byte (range 32 64)))
      sig1 (.getBytes "sig-one" "UTF-8")
      sig2 (.getBytes "sig-two" "UTF-8")
      p {:extensions [[1 (.getBytes "aa" "UTF-8")]]
         :start 4 :end 8
         :inclusion-proof [h1 h2]
         :signatures [{:cosigner-id (.getBytes "abc" "UTF-8") :signature sig1}
                      {:cosigner-id (.getBytes "abd" "UTF-8") :signature sig2}]}
      enc (cert/encode-mtc-proof p)
      dec (cert/decode-mtc-proof enc)]
  (check "start" 4 (:start dec))
  (check "end" 8 (:end dec))
  (check "extensions count" 1 (count (:extensions dec)))
  (check "inclusion-proof count" 2 (count (:inclusion-proof dec)))
  (check "inclusion-proof h1" true (m/bytes= h1 (first (:inclusion-proof dec))))
  (check "sig count" 2 (count (:signatures dec)))
  (check "sig0 id" true (m/bytes= (.getBytes "abc" "UTF-8") (:cosigner-id (first (:signatures dec)))))
  (check "sig1 id" true (m/bytes= (.getBytes "abd" "UTF-8") (:cosigner-id (second (:signatures dec)))))
  (check "re-encode stable" (hex enc) (hex (cert/encode-mtc-proof dec))))

;; duplicate cosigner ids rejected
(let [p {:extensions [] :start 0 :end 1 :inclusion-proof []
         :signatures [{:cosigner-id (.getBytes "abc" "UTF-8") :signature (.getBytes "a" "UTF-8")}
                      {:cosigner-id (.getBytes "abc" "UTF-8") :signature (.getBytes "b" "UTF-8")}]}]
  (check "duplicate cosigner id rejected" true
         (try (cert/decode-mtc-proof (cert/encode-mtc-proof p)) false (catch Throwable _ true))))

;; mis-ordered cosigner ids rejected
(let [p {:extensions [] :start 0 :end 1 :inclusion-proof []
         :signatures [{:cosigner-id (.getBytes "b" "UTF-8") :signature (.getBytes "a" "UTF-8")}
                      {:cosigner-id (.getBytes "a" "UTF-8") :signature (.getBytes "b" "UTF-8")}]}]
  (check "mis-ordered cosigner id rejected" true
         (try (cert/decode-mtc-proof (cert/encode-mtc-proof p)) false (catch Throwable _ true))))

(println "All certificate tests passed")
