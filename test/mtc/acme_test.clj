;; ACME constants.
;; Run: cd mtc && jolt run test/mtc/acme_test.clj
(ns mtc.test.acme
  (:require [mtc.acme :as acme]
            [mtc.iana :as iana]))

(defn check [label expected got]
  (if (= expected got)
    (println (str "PASS " label))
    (do (println (str "FAIL " label)) (println (str "  expected " (pr-str expected))) (println (str "  got      " (pr-str got))) (System/exit 1))))

(check "link relation" "acme-optional-alternate" acme/link-relation)
(check "content type" "application/pem-certificate-chain-with-properties" acme/content-type)
(check "iana registry values" true (= [iana/log-entry-type-null iana/log-entry-type-tbs-cert] [0 1]))

(println "All ACME tests passed")
