;; Trust anchor IDs and the TLS trust_anchors extension.
;; Run: cd mtc && jolt run test/mtc/anchors_test.clj
(ns mtc.test.anchors
  (:require [mtc.anchors :as a]
            [jolt.der :as der]))

(defn check [label expected got]
  (if (= expected got)
    (println (str "PASS " label))
    (do (println (str "FAIL " label)) (println (str "  expected " (pr-str expected))) (println (str "  got      " (pr-str got))) (System/exit 1))))

(check "log-id" [32473 100 0 8] (a/log-id [32473 100] 8))
(check "landmark-id" [32473 100 1 8 42] (a/landmark-id [32473 100] 8 42))
(check "landmark-group-id" [32473 100 2 8 42] (a/landmark-group-id [32473 100] 8 42))
(check "landmark-group-members"
       [[32473 100] [32473 100 1 8 0] [32473 100 1 8 1] [32473 100 1 8 2]]
       (a/landmark-group-members [32473 100] 8 2))

;; TrustAnchorID TLS struct round-trip (opaque<1..32>, RELATIVE-OID contents)
(let [enc (a/encode-trust-anchor-id [32473 1])
      dec (a/decode-trust-anchor-id enc)]
  (check "trust-anchor-id roundtrip" [32473 1] dec)
  (check "trust-anchor-id wire" "0481fd5901"
         (apply str (map (fn [x] (format "%02x" (bit-and x 0xff))) enc))))

;; trust_anchors lists
(let [ids [[32473 1] [32473 100 1 8 42]]
      enc (a/encode-requested-trust-anchor-list ids)]
  (check "requested list roundtrip" ids (a/decode-trust-anchor-id-list enc)))

(println "All anchor tests passed")
