;; RFC Appendix C test vectors for the subtree algorithms.
;; Run: cd mtc && jolt run test/mtc/subtree_test.clj
(ns mtc.test.subtree
  (:require [clojure.string :as str]
            [mtc.sha256 :as sha]
            [mtc.merkle :as m]
            [mtc.subtree :as st]
            [mtc.covering :as cov]))

;; A tree D with leaf d[i] = 0x00, 0x01, ... (single bytes), enough for n<=130.
(def D (vec (map (fn [i] (byte-array [i])) (range 131))))
(def TBL (m/node-table D))

(defn roll-hash [lines]
  (sha/hex-digest (.getBytes (str/join "" lines) "UTF-8")))

(defn now [] (System/currentTimeMillis))

(defn check [label expected got]
  (if (= expected got)
    (println (str "PASS " label))
    (do (println (str "FAIL " label)) (println (str "  expected " expected)) (println (str "  got      " got)) (System/exit 1))))

;; --- C.1.1 subtree hashes --------------------------------------------------
(defn c11 []
  (let [lines (atom [])]
    (doseq [end (range 131)]
      (doseq [start (range (inc end))]
        (when (st/valid-subtree? start end)
          (swap! lines conj (str "[" start ", " end ") " (sha/hex (m/mth TBL start end)) "\n")))))
    (roll-hash @lines)))

;; --- C.1.2 inclusion proofs -------------------------------------------------
(defn c12 []
  (let [lines (atom [])]
    (doseq [end (range 131)]
      (doseq [start (range (inc end))]
        (when (st/valid-subtree? start end)
          (doseq [index (range start end)]
            (let [proof (m/inclusion-path-tbl TBL (- index start) start end)
                  line (atom (str index " [" start ", " end ")"))]
              (doseq [p proof] (swap! line str " " (sha/hex p)))
              (swap! line str "\n")
              (swap! lines conj @line))))))
    (roll-hash @lines)))

;; --- C.1.3 consistency proofs -----------------------------------------------
(defn c13 []
  (let [lines (atom [])]
    (doseq [n (range 131)]
      (doseq [end (range (inc n))]
        (doseq [start (range (inc end))]
          (when (st/valid-subtree? start end)
            (let [proof (st/subtree-proof-tbl TBL start end n)
                  line (atom (str "[" start ", " end ") " n))]
              (doseq [p proof] (swap! line str " " (sha/hex p)))
              (swap! line str "\n")
              (swap! lines conj @line))))))
    (roll-hash @lines)))

;; --- C.1.4 covering subtrees ------------------------------------------------
(defn c14 []
  (let [lines (atom [])]
    (doseq [end (range 131)]
      (doseq [start (range (inc end))]
        (let [[[ls le] [rs re]] (cov/find-subtrees start end)]
          (swap! lines conj (str "[" ls ", " le ") [" rs ", " re ")\n")))))
    (roll-hash @lines)))

(let [t (now)] (check "C.1.1 subtree hashes" "b82806ad4265bb151c1119c0f4db437bb4d1a1f887b3a7fba1cd4ebf552e3e81" (c11)) (println "  " (- (now) t) "ms"))
(let [t (now)] (check "C.1.2 inclusion proofs" "ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f" (c12)) (println "  " (- (now) t) "ms"))
(let [t (now)] (check "C.1.3 consistency proofs" "10fa99b37bf9bf9ffa26b412fbd98bd75363256d0b75d61bc4538b9c9c5a0a74" (c13)) (println "  " (- (now) t) "ms"))
(let [t (now)] (check "C.1.4 covering subtrees" "7fd9c8b926e9d2b5cf831560e8ce295a5ef97ad5c5ede4ea0dea28a8c8fc8bb0" (c14)) (println "  " (- (now) t) "ms"))

(println "All accumulated vectors passed")
