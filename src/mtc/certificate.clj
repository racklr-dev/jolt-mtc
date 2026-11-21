;; RFC 6 — the certificate format (MTCProof) and construction.
(ns mtc.certificate
  "RFC Section 6: Certificates.

  A Merkle Tree Certificate is an X.509 Certificate whose signatureValue
  is an MTCProof (no ASN.1 wrapping), with signatureAlgorithm OID
  id-alg-mtcProof (1.3.6.1.5.5.7.6.67):

    struct {
        MTCLogEntryExtension extensions<0..2^16-1>;
        uint48 start; uint48 end;
        opaque inclusion_proof<0..2^16-1>;   ; concatenated hashes
        Cosignature signatures<0..2^24-1>;
    } MTCProof;
    struct {
        TrustAnchorID cosigner_id;           ; opaque<1..2^8-1>
        opaque signature<0..2^16-1>;
    } Cosignature;

  serialNumber = (log_number << 48) | index  (RFC 6.2).  signatures must
  have unique cosigner_ids ordered by (length, then lexicographic); the
  decoder rejects duplicates and wrong order."
  (:require [jolt.bit :as bit]
            [jolt.tls :as tls]
            [mtc.entry :as entry]))

(defn serial-number
  "RFC 6.2: the certificate serial number (log_number << 48) | index, as a
  uint64 (Long)."
  [log-number index]
  (bit-or (unchecked-long (bit-shift-left (bit/u64 log-number) 48))
          (bit/u64 index)))

(defn- slice [bytes off len]
  (let [out (byte-array len)]
    (dotimes [i len] (aset out i (aget bytes (+ off i))))
    out))

(defn- split-hashes
  "Split a concatenated inclusion proof into 32-byte hashes."
  [bytes]
  (let [n (quot (alength bytes) 32)]
    (when-not (= (* n 32) (alength bytes))
      (throw (ex-info "inclusion proof length is not a multiple of 32"
                      {:len (alength bytes)})))
    (mapv (fn [i] (slice bytes (* 32 i) 32)) (range n))))

(defn- compare-bytes [a b]
  (loop [i 0]
    (if (= i (alength a))
      0
      (let [d (- (bit-and (aget a i) 0xFF) (bit-and (aget b i) 0xFF))]
        (if (zero? d) (recur (inc i)) (if (pos? d) 1 -1))))))

(defn- cosigner-id-cmp [a b]
  (let [la (alength a) lb (alength b)]
    (cond (< la lb) -1 (> la lb) 1 :else (compare-bytes a b))))

(defn- encode-cosignature [{:keys [cosigner-id signature]}]
  (tls/concat-bytes (tls/varlen 1 cosigner-id) (tls/varlen 2 signature)))

(defn encode-mtc-proof
  "Encode an MTCProof. Keys: :extensions (vector of [type data]), :start
  :end (uint48), :inclusion-proof (vector of 32-byte hashes), :signatures
  (vector of {:cosigner-id bytes :signature bytes})."
  [{:keys [extensions start end inclusion-proof signatures]}]
  (tls/concat-bytes
    (entry/encode-extensions extensions)
    (tls/u48 start)
    (tls/u48 end)
    (tls/varlen 2 (apply tls/concat-bytes inclusion-proof))
    (tls/varlen 3 (apply tls/concat-bytes (map encode-cosignature signatures)))))

(defn sort-signatures
  "Sort cosignatures by cosigner_id (shorter first, then lexicographic), the
  RFC 6.2 ordering."
  [signatures]
  (sort-by :cosigner-id (fn [a b] (neg? (cosigner-id-cmp a b))) signatures))

(defn grease-cosignature
  "A GREASE cosignature (RFC 6.2): an unused cosigner ID + arbitrary bytes."
  [cosigner-id-bytes sig-bytes]
  {:cosigner-id cosigner-id-bytes :signature sig-bytes})

(defn add-grease
  "Insert GREASE cosignatures into an MTCProof, keeping strict ordering."
  [mtc-proof greases]
  (assoc mtc-proof :signatures (sort-signatures (concat (:signatures mtc-proof) greases))))

(defn decode-mtc-proof
  "Decode an MTCProof into the same keyed map. Rejects duplicate or
  mis-ordered cosigner_ids (RFC 6.2)."
  [bytes]
  (let [[extensions off] (entry/decode-extensions bytes 0)
        [start off] (tls/read-uint bytes off 6)
        [end off] (tls/read-uint bytes off 6)
        [ip off] (tls/read-varlen bytes off 2)
        [sig-bytes off] (tls/read-varlen bytes off 3)
        inclusion-proof (split-hashes ip)]
    (when-not (= off (alength bytes))
      (throw (ex-info "trailing bytes after MTCProof" {:off off})))
    {:extensions extensions
     :start start :end end
     :inclusion-proof inclusion-proof
     :signatures
     (loop [i 0 acc [] prev nil]
       (if (>= i (alength sig-bytes))
         acc
         (let [[cid i] (tls/read-varlen sig-bytes i 1)
               [sig i] (tls/read-varlen sig-bytes i 2)]
           (when (and prev (not (neg? (cosigner-id-cmp prev cid))))
             (throw (ex-info "cosigner_ids not strictly ordered"
                             {:prev prev :cur cid})))
           (recur i (conj acc {:cosigner-id cid :signature sig}) cid))))}))
