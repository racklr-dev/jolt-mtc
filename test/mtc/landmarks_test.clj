;; Landmark sequences and publish format.
;; Run: cd mtc && jolt run test/mtc/landmarks_test.clj
(ns mtc.test.landmarks
  (:require [mtc.landmarks :as lm]
            [jolt.subtree :as st]
            [jolt.covering :as cov]))

(defn check [label expected got]
  (if (= expected got)
    (println (str "PASS " label))
    (do (println (str "FAIL " label)) (println (str "  expected " (pr-str expected))) (println (str "  got      " (pr-str got))) (System/exit 1))))

(def seq0 [{:number 0 :tree-size 0 :expiry 0}
           {:number 1 :tree-size 100 :expiry 1000}
           {:number 2 :tree-size 200 :expiry 2000}
           {:number 3 :tree-size 300 :expiry 3000}])

;; landmark subtrees for L=2 cover [100, 200)
(let [[[ls le] [rs re]] (lm/landmark-subtrees seq0 2)]
  (check "L=2 left valid" true (st/valid-subtree? ls le))
  (check "L=2 right valid" true (st/valid-subtree? rs re))
  (check "L=2 covers" [[ls le] [rs re]] (cov/find-subtrees 100 200)))

;; landmark zero
(check "L=0 empty" [[0 0] [0 0]] (lm/landmark-subtrees seq0 0))

;; publish/decode round-trip at now=2500: active = landmark 3 only
(let [now 2500
      text (lm/encode-landmarks seq0 now)
      dec (lm/decode-landmarks text now)]
  (check "publish header" "3\n300 3000\n200 2000\n" text)
  (check "decode count" 2 (count dec))
  (check "decode [0]" {:number 3 :tree-size 300 :expiry 3000} (first dec))
  (check "decode [1]" {:number 2 :tree-size 200 :expiry 2000} (second dec)))

;; decoder rejections
(let [now 2500]
  (doseq [doc ["3\n300 3000\n200 2000"
               "3\n300 3000\n300 3000\n"
               "3\n300 3000\n200 3000\n"
               "3\n300 3000\n"
               "3\n300  3000\n200 2000\n"
               "3\n300 3000\n200 02000\n"]]
    (check (str "reject " (pr-str doc)) true
           (try (lm/decode-landmarks doc now) false (catch Throwable _ true)))))

(println "All landmarks tests passed")
