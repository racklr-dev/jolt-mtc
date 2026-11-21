;; RFC 5.2.1 — MTCLogEntry and TBSCertificateLogEntry (what gets logged).
(ns mtc.entry
  "RFC Section 5.2.1: Log Entries.

  An issuance log entry is an MTCLogEntry (TLS presentation language):

    struct {
        MTCLogEntryExtension extensions<0..2^16-1>;  ; TLV list, sorted
        MTCLogEntryType type;                        ; null_entry(0) | tbs_cert_entry(1)
        select (type) { ... }
    } MTCLogEntry;

  For tbs_cert_entry, the payload is the DER contents octets of a
  TBSCertificateLogEntry (the fields of TBSCertificate minus signature
  and algorithm, with subjectPublicKeyInfoHash added).  Name / Validity /
  AlgorithmIdentifier / Extensions are opaque DER blobs supplied by the
  caller (a full RFC5280 codec is out of scope)."
  (:require [mtc.der :as der]))

(def null-entry 0)
(def tbs-cert-entry 1)

(defn- u8 [b] (bit-and b 0xFF))

(defn- u16 [n]
  (byte-array [(unchecked-byte (bit-and (bit-shift-right n 8) 0xFF))
               (unchecked-byte (bit-and n 0xFF))]))

(defn- bcat [& xs]
  (let [parts (mapv (fn [x] (if (number? x) (byte-array [(unchecked-byte x)]) x)) xs)
        total (reduce + 0 (map alength parts))
        out (byte-array total)]
    (loop [off 0 ps (seq parts)]
      (when-let [p (first ps)]
        (dotimes [i (alength p)] (aset out (+ off i) (aget p i)))
        (recur (+ off (alength p)) (next ps))))
    out))

(defn- slice [bytes off len]
  (let [out (byte-array len)]
    (dotimes [i len] (aset out i (aget bytes (+ off i))))
    out))

;; --- MTCLogEntryExtension list -----------------------------------------------

(defn encode-extensions
  "Encode a list of [ext-type ext-data] extensions as the
  extensions<0..2^16-1> field (2-byte total length + TLVs)."
  [extensions]
  (let [ext-body (reduce (fn [acc [et ed]]
                           (bcat acc (u16 et) (u16 (alength ed)) ed))
                         (byte-array 0)
                         extensions)]
    (bcat (u16 (alength ext-body)) ext-body)))

(defn decode-extensions
  "Decode an extensions<0..2^16-1> field starting at offset off of bytes.
  Returns [extensions next-offset], extensions a vector of [ext-type ext-data]."
  [bytes off]
  (let [ext-len (+ (* 256 (u8 (aget bytes off))) (u8 (aget bytes (inc off))))
        ext-end (+ off 2 ext-len)
        extensions (loop [i (+ off 2) acc []]
                     (if (>= i ext-end)
                       acc
                       (let [et (+ (* 256 (u8 (aget bytes i))) (u8 (aget bytes (inc i))))
                             dl (+ (* 256 (u8 (aget bytes (+ i 2)))) (u8 (aget bytes (+ i 3))))
                             data (slice bytes (+ i 4) dl)]
                         (recur (+ i 4 dl) (conj acc [et data])))))]
    [extensions ext-end]))

;; --- MTCLogEntry (TLS presentation) -----------------------------------------

(defn encode-mtc-log-entry
  "Encode an MTCLogEntry. `extensions` is a vector of [ext-type ext-data]
  (ext-data a byte array); `type` is null-entry or tbs-cert-entry; `payload`
  is a byte array (nil -> empty)."
  [extensions type payload]
  (bcat (encode-extensions extensions)
        (byte-array [(unchecked-byte type)])
        (or payload (byte-array 0))))

(defn decode-mtc-log-entry
  "Decode an MTCLogEntry. Returns {:extensions [[ext-type ext-data] ...]
  :type n :payload bytes}."
  [bytes]
  (let [[extensions ext-end] (decode-extensions bytes 0)
        type (u8 (aget bytes ext-end))
        payload (slice bytes (inc ext-end) (- (alength bytes) (inc ext-end)))]
    {:extensions extensions :type type :payload payload}))

;; --- TBSCertificateLogEntry (DER SEQUENCE) -----------------------------------

(defn encode-tbs-cert-log-entry
  "DER-encode a TBSCertificateLogEntry (RFC 5.2.1).

  Keys:
    :version                     (optional; omitted when v1/0)
    :issuer :validity :subject   opaque DER blobs (X.509 Name / Validity)
    :subject-public-key-algorithm opaque DER AlgorithmIdentifier
    :subject-public-key-info-hash 32-byte hash
    :issuer-unique-id :subject-unique-id  (optional) raw BIT STRING content
    :extensions                  (optional) opaque DER Extensions SEQUENCE"
  [{:keys [version issuer validity subject subject-public-key-algorithm
           subject-public-key-info-hash issuer-unique-id subject-unique-id
           extensions]}]
  (der/encode
    (into [:seq]
          (concat
            (when (and version (not (zero? version)))
              [[:ctx 0 [:int version]]])
            [[:raw issuer]
             [:raw validity]
             [:raw subject]
             [:raw subject-public-key-algorithm]
             [:octets subject-public-key-info-hash]]
            (when issuer-unique-id [[:ctx* 1 issuer-unique-id]])
            (when subject-unique-id [[:ctx* 2 subject-unique-id]])
            (when extensions [[:ctx 3 [:raw extensions]]])))))

(defn decode-tbs-cert-log-entry
  "Decode a DER TBSCertificateLogEntry into the same keyed map that
  encode-tbs-cert-log-entry accepts (opaque fields as DER blobs)."
  [bytes]
  (when-not (= 0x30 (u8 (aget bytes 0)))
    (throw (ex-info "TBSCertificateLogEntry must be a SEQUENCE" {})))
  (let [[_ outer-body _] (der/read-tlv bytes 0)
        field-bytes (fn [off fend] (slice outer-body off (- fend off)))]
    (loop [off 0 acc {} saw30 0]
      (if (>= off (alength outer-body))
        acc
        (let [[ftag fbody fend] (der/read-tlv outer-body off)]
          (case ftag
            0xA0 (let [[dv _] (der/decode fbody)]
                   (recur fend (assoc acc :version (second dv)) saw30))
            0x30 (recur fend
                        (assoc acc (case saw30
                                     0 :issuer
                                     1 :validity
                                     2 :subject
                                     3 :subject-public-key-algorithm)
                               (field-bytes off fend))
                        (inc saw30))
            0x04 (recur fend (assoc acc :subject-public-key-info-hash fbody) saw30)
            0x81 (recur fend (assoc acc :issuer-unique-id fbody) saw30)
            0x82 (recur fend (assoc acc :subject-unique-id fbody) saw30)
            0xA3 (recur fend (assoc acc :extensions fbody) saw30)
            (throw (ex-info "unexpected TBSCertificateLogEntry field tag" {:tag ftag}))))))))
