;; FIPS 180-4 known-answer tests for mtc.sha256.
;; Run: cd mtc && jolt run test/mtc/sha256_test.clj
(ns mtc.test.sha256
  (:require [mtc.sha256 :as s]))

(def kat-vectors
  [["" "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
   ["abc" "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"]
   ["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"]])

(defn check [label expected got]
  (if (= expected got)
    (println (str "PASS " label))
    (do (println (str "FAIL " label)) (println (str "  expected " expected)) (println (str "  got      " got)) (System/exit 1))))

(doseq [[in expected] kat-vectors]
  (check (str "sha256 " (pr-str (subs in 0 (min 20 (count in)))))
         expected
         (s/hex-digest (.getBytes in "UTF-8"))))

(println "All SHA-256 KATs passed")
