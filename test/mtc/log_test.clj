;; Issuance log: incremental append + root + proofs.
;; Run: cd mtc && jolt run test/mtc/log_test.clj
(ns mtc.test.log
  (:require [mtc.log :as log]
            [jolt.merkle :as m]
            [jolt.subtree :as st]))

(defn check [label expected got]
  (if (= expected got)
    (println (str "PASS " label))
    (do (println (str "FAIL " label)) (println (str "  expected " (pr-str expected))) (println (str "  got      " (pr-str got))) (System/exit 1))))

(def entries (vec (map (fn [i] (byte-array [i])) (range 20))))
(def L (reduce log/append! (log/new-log 1) entries))

(check "tree-size" 20 (log/tree-size L))
(check "incremental root = MTH" true (m/bytes= (m/merkle-tree-hash entries) (log/root-hash L)))

;; inclusion proofs against the whole tree [0, 20)
(doseq [i (range 20)]
  (let [proof (log/inclusion-proof L 0 20 i)
        eh (m/leaf-hash (entries i))]
    (check (str "inclusion proof " i) true
           (st/verify-inclusion-proof 0 20 i eh (log/root-hash L) proof))))

;; consistency proofs for a few subtrees
(doseq [[s e] [[0 20] [0 8] [8 16] [8 12] [16 20] [4 8] [12 13]]]
  (let [proof (log/consistency-proof L s e)
        nh (log/subtree-hash L s e)]
    (check (str "consistency " s " " e) true
           (st/verify-consistency-proof s e (log/tree-size L) nh (log/root-hash L) proof))))

(println "All log tests passed")
