;; Landmark-relative construction (RFC 6.4.4) + GREASE cosignatures (RFC 6.2).
;; Run: cd mtc && jolt run test/mtc/landmark_cert_test.clj
(ns mtc.test.landmark-cert
  (:require [mtc.landmarks :as lm]
            [mtc.certificate :as cert]
            [mtc.merkle :as m]
            [mtc.subtree :as st]))

(defn check [label expected got]
  (if (= expected got)
    (println (str "PASS " label))
    (do (println (str "FAIL " label)) (println (str "  expected " (pr-str expected))) (println (str "  got      " (pr-str got))) (System/exit 1))))

(def entries (vec (map (fn [i] (byte-array [i])) (range 20))))
(def nt (m/node-table entries))
(def ls [{:number 0 :tree-size 0 :expiry 0}
         {:number 1 :tree-size 8 :expiry 1000}
         {:number 2 :tree-size 16 :expiry 2000}
         {:number 3 :tree-size 20 :expiry 3000}])

(check "landmark-for-index" 1 (:number (lm/landmark-for-index ls 5)))
(check "landmark-subtree-for-index" [4 8] (lm/landmark-subtree-for-index ls 5))

(let [idx 5
      [s e] (lm/landmark-subtree-for-index ls idx)
      p (lm/landmark-relative-proof entries ls idx [])]
  (check "landmark-relative start/end" [4 8] [(:start p) (:end p)])
  (check "landmark-relative proof verifies" true
         (st/verify-inclusion-proof s e idx (m/leaf-hash (entries idx)) (m/mth nt s e) (:inclusion-proof p))))

;; GREASE cosignatures stay strictly ordered
(let [p {:extensions [] :start 0 :end 1 :inclusion-proof []
         :signatures [{:cosigner-id (.getBytes "b" "UTF-8") :signature (byte-array [1])}]}
      g (cert/grease-cosignature (.getBytes "a" "UTF-8") (byte-array [2 3]))
      p2 (cert/add-grease p [g])
      dec (cert/decode-mtc-proof (cert/encode-mtc-proof p2))]
  (check "grease ordered" 2 (count (:signatures dec)))
  (check "grease first" true (m/bytes= (.getBytes "a" "UTF-8") (:cosigner-id (first (:signatures dec))))))

(println "All landmark-cert tests passed")
