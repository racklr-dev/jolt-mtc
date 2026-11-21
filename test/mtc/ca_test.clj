;; MTCCertificationAuthority encode/decode.
;; Run: cd mtc && jolt run test/mtc/ca_test.clj
(ns mtc.test.ca
  (:require [mtc.ca :as ca]
            [mtc.der :as der]
            [mtc.merkle :as m]))

(defn hex [b] (apply str (map (fn [x] (format "%02x" (bit-and x 0xff))) b)))

(defn check [label expected got]
  (if (= expected got)
    (println (str "PASS " label))
    (do (println (str "FAIL " label)) (println (str "  expected " (pr-str expected))) (println (str "  got      " (pr-str got))) (System/exit 1))))

(let [sig-alg (der/encode [:seq [:oid [1 2 840 113549 1 1 1]] [:null]])
      ca {:sig-alg sig-alg :min-serial 281474976710656 :max-serial 18446744073709551615}
      enc (ca/encode-mtc-ca ca)
      dec (ca/decode-mtc-ca enc)]
  (check "sig-alg roundtrip" true (m/bytes= sig-alg (:sig-alg dec)))
  (check "min-serial" 281474976710656 (:min-serial dec))
  (check "max-serial" 18446744073709551615 (:max-serial dec))
  (check "re-encode stable" (hex enc) (hex (ca/encode-mtc-ca dec))))

(check "oid arcs" [1 3 6 1 5 5 7 1 38] ca/mtc-ca-sha256-oid)

;; full X.509 Extension wrapper (RFC 5.5)
(let [ca {:sig-alg (der/encode [:seq [:oid [1 2 840 113549 1 1 1]] [:null]])
          :min-serial 281474976710656
          :max-serial 18446744073709551615}
      ext (ca/encode-mtc-ca-extension ca)
      dec (ca/decode-mtc-ca-extension ext)]
  (check "extension roundtrip min-serial" 281474976710656 (:min-serial dec))
  (check "extension roundtrip max-serial" 18446744073709551615 (:max-serial dec))
  (check "extension re-encode stable" (hex ext) (hex (ca/encode-mtc-ca-extension dec))))

(println "All CA tests passed")
