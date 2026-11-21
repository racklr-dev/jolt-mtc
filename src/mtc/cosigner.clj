;; RFC 5.3 — CosignedSubtree (cosignature format).
(ns mtc.cosigner
  "RFC Section 5.3: Cosigners and the subtree signature format.

  A cosigner follows an append-only view of a log and signs subtrees.
  The signed structure (TLS presentation language):

    opaque HashValue[HASH_SIZE];
    struct {
        uint8 label[12] = \"subtree/v1\\n\\0\";   ; domain separation
        opaque cosigner_name<1..2^8-1>;
        uint64 timestamp;                       ; 0 => no time statement
        opaque log_origin<1..2^8-1>;
        uint64 start; uint64 end;
        HashValue subtree_hash;
    } CosignedSubtree;

  cosigner_name / log_origin encode a trust anchor ID as the ASCII
  string oid/1.3.6.1.4.1.<arcs...> (RFC 5.3.1).  Signature algorithms are
  pluggable: sign / verify take the signature primitive as a function."
  (:require [clojure.string :as str]
            [mtc.tls :as tls]
            [mtc.der :as der]))

(def label-bytes
  "The fixed 12-byte domain-separation label: subtree/v1, newline, NUL."
  (byte-array (concat (map int "subtree/v1") [0x0A 0x00])))

(def trust-anchor-prefix [1 3 6 1 4 1])

(defn trust-anchor-name
  "The ASCII string oid/1.3.6.1.4.1.<arcs> for a trust anchor ID (RFC 5.3.1).
  arcs is the PEN-relative trust anchor ID (e.g. [32473 1])."
  [arcs]
  (str "oid/1.3.6.1.4.1." (str/join "." arcs)))

(defn cosigner-id-bytes
  "Binary representation of a cosigner ID (a trust anchor ID): the DER OID
  content of 1.3.6.1.4.1.<arcs>."
  [arcs]
  (der/oid-content (into trust-anchor-prefix arcs)))

(defn cosigner-id-arcs
  "Parse cosigner-id-bytes back to PEN-relative arcs."
  [bytes]
  (vec (drop (count trust-anchor-prefix) (der/oid-arcs bytes))))

(defn- bytes->str [b]
  (apply str (map char b)))

(defn- slice [bytes off len]
  (let [out (byte-array len)]
    (dotimes [i len] (aset out i (aget bytes (+ off i))))
    out))

(defn encode-cosigned-subtree
  "Encode a CosignedSubtree. Keys: :cosigner-name (str), :timestamp (uint64),
  :log-origin (str), :start :end (uint64), :subtree-hash (32 bytes)."
  [{:keys [cosigner-name timestamp log-origin start end subtree-hash]}]
  (tls/concat-bytes
    label-bytes
    (tls/varlen 1 (.getBytes cosigner-name "UTF-8"))
    (tls/u64 timestamp)
    (tls/varlen 1 (.getBytes log-origin "UTF-8"))
    (tls/u64 start)
    (tls/u64 end)
    subtree-hash))

(defn decode-cosigned-subtree
  "Decode a CosignedSubtree. Returns the same keyed map (strings for the
  two names, Longs for timestamp/start/end, byte array for subtree-hash)."
  [bytes]
  (let [label (slice bytes 0 12)
        [cn off] (tls/read-varlen bytes 12 1)
        [ts off] (tls/read-uint bytes off 8)
        [lo off] (tls/read-varlen bytes off 1)
        [start off] (tls/read-uint bytes off 8)
        [end off] (tls/read-uint bytes off 8)
        sh (slice bytes off 32)]
    {:label label
     :cosigner-name (bytes->str cn)
     :timestamp ts
     :log-origin (bytes->str lo)
     :start start
     :end end
     :subtree-hash sh}))

(defn sign
  "Sign a CosignedSubtree. `sign-fn` is (fn [private-key message-bytes] -> sig)."
  [sign-fn private-key cst]
  (sign-fn private-key (encode-cosigned-subtree cst)))

(defn verify
  "Verify a cosignature over a CosignedSubtree. `verify-fn` is
  (fn [public-key message-bytes signature] -> bool)."
  [verify-fn public-key cst signature]
  (verify-fn public-key (encode-cosigned-subtree cst) signature))
