;; RFC Appendix C.2 — large-tree subtree validity and covering vectors.
;; Run: cd mtc && jolt run test/mtc/large_test.clj
(ns mtc.test.large
  (:require [mtc.subtree :as st]
            [mtc.covering :as cov]))

(defn u [x] (unchecked-long x))

(defn check [label expected got]
  (if (= expected got)
    (println (str "PASS " label))
    (do (println (str "FAIL " label)) (println (str "  expected " (pr-str expected))) (println (str "  got      " (pr-str got))) (System/exit 1))))

;; C.2.1 — subtree validity at large sizes.
(let [valid [[0 (+ (bit-shift-left 1 47) 1)]
             [0 (- (bit-shift-left 1 48) 1)]
             [0 (+ (bit-shift-left 1 62) 1)]
             [0 (- (bit-shift-left 1 63) 1)]
             [0 (u 0x8000000000000001)]   ; 2^63 + 1
             [0 (u 0xffffffffffffffff)]]   ; 2^64 - 1
      invalid [[(bit-shift-left 1 46) (+ (bit-shift-left 1 47) 1)]
               [(bit-shift-left 1 46) (- (bit-shift-left 1 48) 1)]
               [(bit-shift-left 1 61) (+ (bit-shift-left 1 62) 1)]
               [(bit-shift-left 1 61) (- (bit-shift-left 1 63) 1)]
               [(bit-shift-left 1 62) (u 0x8000000000000001)]   ; 2^63 + 1
               [(bit-shift-left 1 62) (u 0xffffffffffffffff)]]]  ; 2^64 - 1
  (doseq [[s e] valid]
    (check (str "valid " s " " e) true (st/valid-subtree? s e)))
  (doseq [[s e] invalid]
    (check (str "invalid " s " " e) false (st/valid-subtree? s e))))

;; C.2.4 — efficient covering of large intervals: [input -> [left right]].
(let [vectors
      [[[(u 0x0) (u 0x800000000000)] [[(u 0x0) (u 0x400000000000)] [(u 0x400000000000) (u 0x800000000000)]]]
       [[(u 0x500000000000) (u 0xd00000000000)] [[(u 0x400000000000) (u 0x800000000000)] [(u 0x800000000000) (u 0xd00000000000)]]]
       [[(u 0x7fffffffffff) (u 0x800000000001)] [[(u 0x7fffffffffff) (u 0x800000000000)] [(u 0x800000000000) (u 0x800000000001)]]]
       [[(u 0xfffffffffffe) (u 0xffffffffffff)] [[(u 0xfffffffffffe) (u 0xffffffffffff)] [(u 0xffffffffffff) (u 0xffffffffffff)]]]
       [[(u 0xffffffffffff) (u 0xffffffffffff)] [[(u 0xffffffffffff) (u 0xffffffffffff)] [(u 0xffffffffffff) (u 0xffffffffffff)]]]
       [[(u 0x0) (u 0x4000000000000000)] [[(u 0x0) (u 0x2000000000000000)] [(u 0x2000000000000000) (u 0x4000000000000000)]]]
       [[(u 0x2800000000000000) (u 0x6800000000000000)] [[(u 0x2000000000000000) (u 0x4000000000000000)] [(u 0x4000000000000000) (u 0x6800000000000000)]]]
       [[(u 0x3fffffffffffffff) (u 0x4000000000000001)] [[(u 0x3fffffffffffffff) (u 0x4000000000000000)] [(u 0x4000000000000000) (u 0x4000000000000001)]]]
       [[(u 0x7ffffffffffffffe) (u 0x7fffffffffffffff)] [[(u 0x7ffffffffffffffe) (u 0x7fffffffffffffff)] [(u 0x7fffffffffffffff) (u 0x7fffffffffffffff)]]]
       [[(u 0x7fffffffffffffff) (u 0x7fffffffffffffff)] [[(u 0x7fffffffffffffff) (u 0x7fffffffffffffff)] [(u 0x7fffffffffffffff) (u 0x7fffffffffffffff)]]]
       [[(u 0x0) (u 0x8000000000000000)] [[(u 0x0) (u 0x4000000000000000)] [(u 0x4000000000000000) (u 0x8000000000000000)]]]
       [[(u 0x5000000000000000) (u 0xd000000000000000)] [[(u 0x4000000000000000) (u 0x8000000000000000)] [(u 0x8000000000000000) (u 0xd000000000000000)]]]
       [[(u 0x7fffffffffffffff) (u 0x8000000000000001)] [[(u 0x7fffffffffffffff) (u 0x8000000000000000)] [(u 0x8000000000000000) (u 0x8000000000000001)]]]
       [[(u 0xfffffffffffffffe) (u 0xffffffffffffffff)] [[(u 0xfffffffffffffffe) (u 0xffffffffffffffff)] [(u 0xffffffffffffffff) (u 0xffffffffffffffff)]]]
       [[(u 0xffffffffffffffff) (u 0xffffffffffffffff)] [[(u 0xffffffffffffffff) (u 0xffffffffffffffff)] [(u 0xffffffffffffffff) (u 0xffffffffffffffff)]]]]]
  (doseq [[in expected] vectors]
    (check (str "cover " (pr-str in)) expected (cov/find-subtrees (first in) (second in)))))

(println "All C.2 large-tree vectors passed")
