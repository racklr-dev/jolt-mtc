;; Minimal DER (X.690) encode/decode for the ASN.1 fields MTC needs.
(ns mtc.der
  "Minimal DER encode/decode.

  We need just enough DER for TBSCertificateLogEntry (RFC 5.2.1) and
  MTCCertificationAuthority (RFC 5.5): SEQUENCE, INTEGER, OCTET STRING,
  OBJECT IDENTIFIER, NULL, and context-specific tags.  Not a general X.509
  codec — the full RFC5280 name encoding stays out of scope (callers pass
  Name/Validity/AlgorithmIdentifier as opaque DER blobs).

  Values are tagged lists:
    [:int n]            INTEGER (non-negative)
    [:octets bytes]     OCTET STRING
    [:oid arcs]         OBJECT IDENTIFIER, arcs a vector of non-neg ints
    [:seq & elems]      SEQUENCE of DER values
    [:null]             NULL
    [:ctx n v]          context-specific EXPLICIT [n]
    [:ctx* n bytes]     context-specific IMPLICIT [n] (raw body bytes)")

(defn- u8 [b] (bit-and b 0xFF))

(defn- bcat
  "Concatenate byte arrays, single byte ints, or seqs of byte ints into one
  byte array."
  [& xs]
  (let [parts (mapv (fn [x]
                      (cond
                        (number? x) (byte-array [(unchecked-byte x)])
                        (sequential? x) (byte-array (mapv unchecked-byte x))
                        :else x))
                    xs)
        total (reduce + 0 (map alength parts))
        out (byte-array total)]
    (loop [off 0 ps (seq parts)]
      (when-let [p (first ps)]
        (dotimes [i (alength p)] (aset out (+ off i) (aget p i)))
        (recur (+ off (alength p)) (next ps))))
    out))

(defn- int-bytes
  "Minimal big-endian bytes of a non-negative integer n (n > 0)."
  [n]
  (loop [n n acc ()]
    (if (zero? n)
      (mapv unchecked-byte acc)
      (recur (quot n 256) (cons (bit-and n 0xFF) acc)))))

(defn- encode-length [n]
  (if (<= n 127)
    (byte-array [(unchecked-byte n)])
    (let [b (int-bytes n)]
      (bcat (unchecked-byte (bit-or 0x80 (alength b))) b))))

(defn- tlv [tag body]
  (bcat (unchecked-byte tag) (encode-length (alength body)) body))

(defn encode-int
  "DER INTEGER for a non-negative integer."
  [n]
  (let [body (if (zero? n)
               [0]
               (let [b (int-bytes n)]
                 (if (pos? (bit-and (first b) 0x80))
                   (vec (cons 0 b))
                   b)))]
    (tlv 0x02 (byte-array (mapv unchecked-byte body)))))

(defn encode-octets [bytes] (tlv 0x04 bytes))

(defn encode-null [] (tlv 0x05 (byte-array 0)))

(defn- enc-oid-arc
  "Base-128 encode one OID arc (arc >= 0)."
  [arc]
  (loop [arc arc, groups ()]
    (let [groups (cons (bit-and arc 0x7F) groups)
          arc (quot arc 128)]
      (if (zero? arc)
        (let [n (count groups)]
          (mapv unchecked-byte
                (map-indexed (fn [i g] (if (= i (dec n)) g (bit-or g 0x80))) groups)))
        (recur arc groups)))))

(defn encode-oid
  "DER OBJECT IDENTIFIER from arcs (a vector of non-negative integers)."
  [arcs]
  (let [a0 (first arcs)
        a1 (second arcs)
        first-byte (+ (* 40 a0) a1)
        body (vec (cons first-byte (mapcat enc-oid-arc (nnext arcs))))]
    (tlv 0x06 (byte-array (mapv unchecked-byte body)))))

(declare encode)

(defn encode-seq
  "DER SEQUENCE of DER values (already in tagged-list form)."
  [elems]
  (tlv 0x30 (apply bcat (map encode elems))))

(defn encode
  "Encode a DER value in tagged-list form (see the ns docstring)."
  [v]
  (case (first v)
    :int (encode-int (second v))
    :octets (encode-octets (second v))
    :oid (encode-oid (second v))
    :seq (encode-seq (rest v))
    :null (encode-null)
    :ctx (tlv (bit-or 0xA0 (second v)) (encode (nth v 2)))
    :ctx* (tlv (bit-or 0x80 (second v)) (nth v 2))
    :raw (second v)
    (throw (ex-info "unknown DER value" {:v v}))))

;; --- decode ---------------------------------------------------------------

(defn- read-length [bytes off]
  (let [b1 (u8 (aget bytes off))]
    (if (not (pos? (bit-and b1 0x80)))
      [b1 (inc off)]
      (let [n (bit-and b1 0x7F)]
        (loop [i 0 len 0 off (inc off)]
          (if (= i n)
            [len off]
            (recur (inc i) (+ (* len 256) (u8 (aget bytes off))) (inc off))))))))

(defn- bytes-range [bytes off len]
  (let [out (byte-array len)]
    (dotimes [i len] (aset out i (aget bytes (+ off i))))
    out))

(defn- decode-int [body]
  (if (zero? (alength body))
    0
    (let [neg? (pos? (bit-and (aget body 0) 0x80))
          len (alength body)]
      (loop [i 0 n 0]
        (if (= i len)
          (if neg? (- n (bit-shift-left 1 (* 8 len))) n)
          (recur (inc i) (+ (* n 256) (u8 (aget body i)))))))))

(defn- parse-oid-content [bytes off len]
  (let [end (+ off len)
        fb (u8 (aget bytes off))
        first-arcs [(quot fb 40) (mod fb 40)]]
    (loop [i (inc off) arcs first-arcs cur 0]
      (if (>= i end)
        arcs
        (let [b (u8 (aget bytes i))]
          (if (pos? (bit-and b 0x80))
            (recur (inc i) arcs (+ (* cur 128) (bit-and b 0x7F)))
            (recur (inc i) (conj arcs (+ (* cur 128) b)) 0)))))))

(declare parse-value)

(defn- parse-seq [bytes off len]
  (let [end (+ off len)]
    (loop [i off acc []]
      (if (= i end)
        acc
        (let [[v ni] (parse-value bytes i)]
          (recur ni (conj acc v)))))))

(defn- parse-value [bytes off]
  (let [tag (u8 (aget bytes off))
        [len body-off] (read-length bytes (inc off))
        end (+ body-off len)
        body (bytes-range bytes body-off len)]
    (case tag
      0x02 [[:int (decode-int body)] end]
      0x04 [[:octets body] end]
      0x05 [[:null] end]
      0x06 [[:oid (parse-oid-content bytes body-off len)] end]
      0x30 [(into [:seq] (parse-seq bytes body-off len)) end]
      (cond
        (<= 0xA0 tag 0xBF) (let [[inner iend] (parse-value bytes body-off)]
                             [[:ctx (- tag 0xA0) inner] end])
        (<= 0x80 tag 0x9F) [[:ctx* (- tag 0x80) body] end]
        :else (throw (ex-info "unsupported DER tag" {:tag tag}))))))

(defn read-tlv
  "Read one TLV at offset off without decoding its body. Returns
  [tag body next-offset], where body is the raw content bytes and
  next-offset points just past the TLV."
  [bytes off]
  (let [tag (u8 (aget bytes off))
        [len body-off] (read-length bytes (inc off))
        end (+ body-off len)]
    [tag (bytes-range bytes body-off len) end]))

(defn decode
  "Decode one DER value from bytes. Returns [value rest-bytes]."
  [bytes]
  (let [[v off] (parse-value bytes 0)]
    [v (bytes-range bytes off (- (alength bytes) off))]))
