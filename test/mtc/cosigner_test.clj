;; CosignedSubtree encode/decode + sign/verify.
;; Run: cd mtc && jolt run test/mtc/cosigner_test.clj
(ns mtc.test.cosigner
  (:require [mtc.cosigner :as c]
            [mtc.merkle :as m]
            [mtc.sha256 :as sha]))

(defn check [label expected got]
  (if (= expected got)
    (println (str "PASS " label))
    (do (println (str "FAIL " label)) (println (str "  expected " (pr-str expected))) (println (str "  got      " (pr-str got))) (System/exit 1))))

(check "label length" 12 (alength c/label-bytes))
(check "label bytes" true (m/bytes= (.getBytes "subtree/v1" "UTF-8") (byte-array (map (fn [i] (aget c/label-bytes i)) (range 10)))))
(check "label newline" 0x0A (bit-and (aget c/label-bytes 10) 0xFF))
(check "label nul" 0x00 (bit-and (aget c/label-bytes 11) 0xFF))
(check "trust-anchor-name" "oid/1.3.6.1.4.1.32473.1" (c/trust-anchor-name [32473 1]))

(let [sh (.getBytes "0123456789abcdef0123456789abcdef" "UTF-8")
      cst {:cosigner-name (c/trust-anchor-name [32473 1])
           :timestamp 0
           :log-origin (c/trust-anchor-name [32473 1 1])
           :start 0
           :end 100
           :subtree-hash sh}
      enc (c/encode-cosigned-subtree cst)
      dec (c/decode-cosigned-subtree enc)]
  (check "cosigner-name roundtrip" (:cosigner-name cst) (:cosigner-name dec))
  (check "timestamp roundtrip" 0 (:timestamp dec))
  (check "log-origin roundtrip" (:log-origin cst) (:log-origin dec))
  (check "start roundtrip" 0 (:start dec))
  (check "end roundtrip" 100 (:end dec))
  (check "subtree-hash roundtrip" true (m/bytes= sh (:subtree-hash dec))))

;; pluggable dummy signer: sig = sha256(key || message)
(let [sign (fn [key msg] (sha/digest (byte-array (concat (seq key) (seq msg)))))
      verify (fn [key msg sig] (m/bytes= sig (sign key msg)))
      key (.getBytes "secret" "UTF-8")
      cst {:cosigner-name (c/trust-anchor-name [1])
           :timestamp 0
           :log-origin (c/trust-anchor-name [2])
           :start 0 :end 5
           :subtree-hash (byte-array 32)}
      sig (c/sign sign key cst)]
  (check "sign/verify true" true (c/verify verify key cst sig))
  (check "sign/verify wrong key" false (c/verify verify (.getBytes "other" "UTF-8") cst sig)))

(println "All cosigner tests passed")
