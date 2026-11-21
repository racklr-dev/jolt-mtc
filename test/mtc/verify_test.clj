;; Verification cross-checks: every generated proof must verify, and
;; truncated/extended proofs must fail (RFC C.1.2 steps 2-4, C.1.3 step 2).
;; Run: cd mtc && jolt run test/mtc/verify_test.clj
(ns mtc.test.verify
  (:require [mtc.merkle :as m]
            [mtc.subtree :as st]))

(def D (vec (map (fn [i] (byte-array [i])) (range 131))))
(def TBL (m/node-table D))
(def arbitrary-hash (byte-array 32))

(defn fail [& msgs]
  (println "FAIL" (apply str msgs))
  (System/exit 1))

;; --- positive: inclusion proofs evaluate to their subtree hash ---------------
(let [n 0]
  (doseq [end (range 131)]
    (doseq [start (range (inc end))]
      (when (st/valid-subtree? start end)
        (let [sh (m/mth TBL start end)]
          (doseq [index (range start end)]
            (let [proof (m/inclusion-path-tbl TBL (- index start) start end)
                  eh (m/leaf-hash (D index))
                  got (st/evaluate-inclusion-proof start end index eh proof)]
              (when-not (m/bytes= sh got)
                (fail " inclusion eval " start " " end " " index))
              (when-not (st/verify-inclusion-proof start end index eh sh proof)
                (fail " inclusion verify " start " " end " " index))))))))
  (println "PASS inclusion proofs evaluate + verify"))

;; --- positive: consistency proofs verify --------------------------------------
(doseq [n (range 131)]
  (doseq [end (range (inc n))]
    (doseq [start (range (inc end))]
      (when (st/valid-subtree? start end)
        (let [proof (st/subtree-proof-tbl TBL start end n)
              nh (m/mth TBL start end)
              rh (m/mth TBL 0 n)]
          (when-not (st/verify-consistency-proof start end n nh rh proof)
            (fail " consistency verify " start " " end " " n)))))))
(println "PASS consistency proofs verify")

;; --- negative: truncated/extended inclusion proofs must fail ------------------
(doseq [end (range 131)]
  (doseq [start (range (inc end))]
    (when (st/valid-subtree? start end)
      (doseq [index (range start end)]
        (let [proof (m/inclusion-path-tbl TBL (- index start) start end)
              sh (m/mth TBL start end)
              eh (m/leaf-hash (D index))]
          (when (seq proof)
            (when (st/verify-inclusion-proof start end index eh sh (butlast proof))
              (fail " truncated inclusion accepted"))
            (when (st/verify-inclusion-proof start end index eh sh (conj proof arbitrary-hash))
              (fail " extended inclusion accepted"))))))))
(println "PASS inclusion negative tests")

;; --- negative: truncated/extended consistency proofs must fail ----------------
(doseq [n (range 131)]
  (doseq [end (range (inc n))]
    (doseq [start (range (inc end))]
      (when (st/valid-subtree? start end)
        (let [proof (st/subtree-proof-tbl TBL start end n)
              nh (m/mth TBL start end)
              rh (m/mth TBL 0 n)]
          (when (seq proof)
            (when (st/verify-consistency-proof start end n nh rh (butlast proof))
              (fail " truncated consistency accepted"))
            (when (st/verify-consistency-proof start end n nh rh (conj proof arbitrary-hash))
              (fail " extended consistency accepted"))))))))
(println "PASS consistency negative tests")

(println "All verification cross-checks passed")
