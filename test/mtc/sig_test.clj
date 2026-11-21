;; Real signature algorithms (Ed25519) through jolt-lang/crypto.
;; Run: cd mtc && JOLT_SKIP_MIN_VERSION=1 jolt -A:crypto run test/mtc/sig_test.clj
(ns mtc.test.sig
  (:require [mtc.sig :as sig]
            [mtc.cosigner :as cos]
            [jolt.merkle :as m]))

(defn check [label expected got]
  (if (= expected got)
    (println (str "PASS " label))
    (do (println (str "FAIL " label)) (println (str "  expected " (pr-str expected))) (println (str "  got      " (pr-str got))) (System/exit 1))))

(let [kp (sig/ed25519-key-pair)
      sign (sig/ed25519-signer)
      verify (sig/ed25519-verifier)
      msg (.getBytes "message to sign" "UTF-8")
      s (sign (:private kp) msg)]
  (check "ed25519 verify" true (verify (:public kp) msg s))
  (check "ed25519 wrong key rejected" false (verify (:public (sig/ed25519-key-pair)) msg s))
  (check "ed25519 wrong msg rejected" false (verify (:public kp) (.getBytes "other" "UTF-8") s)))

;; key encoding round-trip (DER SPKI / PKCS#8)
(let [kp (sig/ed25519-key-pair)
      pub (sig/parse-public-key "Ed25519" (sig/public-key-bytes (:public kp)))
      priv (sig/parse-private-key "Ed25519" (sig/private-key-bytes (:private kp)))
      sign (sig/ed25519-signer)
      verify (sig/ed25519-verifier)
      msg (.getBytes "roundtrip" "UTF-8")
      s (sign priv msg)]
  (check "key roundtrip verify" true (verify pub msg s)))

;; CosignedSubtree signed with a real Ed25519 cosigner
(let [kp (sig/ed25519-key-pair)
      sign (sig/ed25519-signer)
      verify (sig/ed25519-verifier)
      cst {:cosigner-name (cos/trust-anchor-name [32473 1])
           :timestamp 0
           :log-origin (cos/trust-anchor-name [32473 1 0 1])
           :start 0 :end 10
           :subtree-hash (byte-array 32)}
      s (cos/sign sign (:private kp) cst)]
  (check "cosigned subtree verifies" true (cos/verify verify (:public kp) cst s))
  (check "cosigned subtree wrong key rejected" false (cos/verify verify (:public (sig/ed25519-key-pair)) cst s)))

(println "All signature tests passed")
