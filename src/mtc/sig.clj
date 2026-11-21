;; Concrete signature algorithms via jolt-lang/crypto (OpenSSL).
(ns mtc.sig
  "Concrete signature algorithms, backed by jolt-lang/crypto's
  java.security.Signature (Ed25519, ECDSA, RSA). Wraps the pluggable cosigner
  seam (mtc.cosigner sign/verify) with real signers/verifiers, plus key
  generation and DER key encoding.

  Requires the :crypto alias (jolt-lang/jolt-crypto), which in turn needs a
  jolt with the FFI/native + host-shim surface and OpenSSL 3 at runtime.")

(defn key-pair
  "Generate a key pair. `alg` is a KeyPairGenerator name, e.g. \"Ed25519\"."
  [alg]
  (let [kp (.generateKeyPair (java.security.KeyPairGenerator/getInstance alg))]
    {:algorithm alg :private (.getPrivate kp) :public (.getPublic kp)}))

(defn signer
  "A cosigner-compatible sign fn: (fn [private-key message-bytes] -> signature)."
  [alg]
  (fn [private-key msg]
    (let [s (java.security.Signature/getInstance alg)]
      (.initSign s private-key)
      (.update s msg)
      (.sign s))))

(defn verifier
  "A cosigner-compatible verify fn: (fn [public-key message-bytes signature] -> bool)."
  [alg]
  (fn [public-key msg sig]
    (try
      (let [s (java.security.Signature/getInstance alg)]
        (.initVerify s public-key)
        (.update s msg)
        (.verify s sig))
      (catch Throwable _ false))))

(defn public-key-bytes [key] (.getEncoded key))
(defn private-key-bytes [key] (.getEncoded key))

(defn parse-public-key
  "Parse a DER SPKI (X.509 SubjectPublicKeyInfo) back into a public key."
  [keyfactory-alg bytes]
  (.generatePublic (java.security.KeyFactory/getInstance keyfactory-alg)
                   (java.security.spec.X509EncodedKeySpec. bytes)))

(defn parse-private-key
  "Parse DER PKCS#8 back into a private key."
  [keyfactory-alg bytes]
  (.generatePrivate (java.security.KeyFactory/getInstance keyfactory-alg)
                    (java.security.spec.PKCS8EncodedKeySpec. bytes)))

;; --- Ed25519 convenience ----------------------------------------------------

(defn ed25519-key-pair [] (key-pair "Ed25519"))
(defn ed25519-signer [] (signer "Ed25519"))
(defn ed25519-verifier [] (verifier "Ed25519"))
