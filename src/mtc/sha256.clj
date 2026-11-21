;; Pure-Clojure SHA-256, needed because jolt provides no MessageDigest.
(ns mtc.sha256
  "Pure-Clojure SHA-256 (FIPS 180-4 / [SHS]).

  jolt's runtime has no java.security.MessageDigest provider, so we
  implement SHA-256 directly over clojure.core bit operations.  The RFC
  RECOMMENDS SHA-256 for the CA's hash function and every Appendix C
  test vector is SHA-256.

  API:
    (digest bytes)     -> 32-byte byte array
    (hex bytes)        -> lowercase hex string
    (hex-digest bytes) -> lowercase hex of the digest"
  (:require [mtc.bit :as bit]))

(def ^:private h0
  [0x6a09e667 0xbb67ae85 0x3c6ef372 0xa54ff53a
   0x510e527f 0x9b05688c 0x1f83d9ab 0x5be0cd19])

(def ^:private k
  [0x428a2f98 0x71374491 0xb5c0fbcf 0xe9b5dba5 0x3956c25b 0x59f111f1 0x923f82a4 0xab1c5ed5
   0xd807aa98 0x12835b01 0x243185be 0x550c7dc3 0x72be5d74 0x80deb1fe 0x9bdc06a7 0xc19bf174
   0xe49b69c1 0xefbe4786 0x0fc19dc6 0x240ca1cc 0x2de92c6f 0x4a7484aa 0x5cb0a9dc 0x76f988da
   0x983e5152 0xa831c66d 0xb00327c8 0xbf597fc7 0xc6e00bf3 0xd5a79147 0x06ca6351 0x14292967
   0x27b70a85 0x2e1b2138 0x4d2c6dfc 0x53380d13 0x650a7354 0x766a0abb 0x81c2c92e 0x92722c85
   0xa2bfe8a1 0xa81a664b 0xc24b8b70 0xc76c51a3 0xd192e819 0xd6990624 0xf40e3585 0x106aa070
   0x19a4c116 0x1e376c08 0x2748774c 0x34b0bcb5 0x391c0cb3 0x4ed8aa4a 0x5b9cca4f 0x682e6ff3
   0x748f82ee 0x78a5636f 0x84c87814 0x8cc70208 0x90befffa 0xa4506ceb 0xbef9a3f7 0xc67178f2])

(defn- u32+
  "Add 32-bit words mod 2^32."
  [& xs]
  (bit-and 0xFFFFFFFF (reduce + 0 xs)))

(defn- rotr [x n] (bit/rotate-right32 x n))
(defn- shr [x n] (unsigned-bit-shift-right x n))

(defn- s0 [x] (bit-xor (rotr x 7) (bit-xor (rotr x 18) (shr x 3))))
(defn- s1 [x] (bit-xor (rotr x 17) (bit-xor (rotr x 19) (shr x 10))))
(defn- S0 [x] (bit-xor (rotr x 2) (bit-xor (rotr x 13) (rotr x 22))))
(defn- S1 [x] (bit-xor (rotr x 6) (bit-xor (rotr x 11) (rotr x 25))))
(defn- ch [x y z] (bit-xor (bit-and x y) (bit-and (bit-not x) z)))
(defn- maj [x y z] (bit-xor (bit-xor (bit-and x y) (bit-and x z)) (bit-and y z)))

(defn- u8 [b] (bit-and b 0xFF))

(defn- block-word
  "The i-th 32-bit big-endian word of the 64-byte block starting at off."
  [bytes off i]
  (let [j (+ off (* 4 i))]
    (bit-or (bit-shift-left (u8 (aget bytes j)) 24)
            (bit-or (bit-shift-left (u8 (aget bytes (inc j))) 16)
                    (bit-or (bit-shift-left (u8 (aget bytes (+ 2 j))) 8)
                            (u8 (aget bytes (+ 3 j))))))))

(defn- schedule
  "Expand a 64-byte block (at off) into the 64-word message schedule."
  [bytes off]
  (loop [i 0 w []]
    (if (= i 16)
      (loop [i 16 w w]
        (if (= i 64)
          w
          (recur (inc i)
                 (conj w (u32+ (nth w (- i 16))
                               (s0 (nth w (- i 15)))
                               (nth w (- i 7))
                               (s1 (nth w (- i 2))))))))
      (recur (inc i) (conj w (block-word bytes off i))))))

(defn- compress-block
  "Run one SHA-256 compression; returns the 8 updated state words."
  [hs bytes off]
  (let [w (schedule bytes off)]
    (loop [i 0
           a (nth hs 0) b (nth hs 1) c (nth hs 2) d (nth hs 3)
           e (nth hs 4) f (nth hs 5) g (nth hs 6) h (nth hs 7)]
      (if (= i 64)
        [(u32+ (nth hs 0) a) (u32+ (nth hs 1) b) (u32+ (nth hs 2) c) (u32+ (nth hs 3) d)
         (u32+ (nth hs 4) e) (u32+ (nth hs 5) f) (u32+ (nth hs 6) g) (u32+ (nth hs 7) h)]
        (let [t1 (u32+ h (S1 e) (ch e f g) (nth k i) (nth w i))
              t2 (u32+ (S0 a) (maj a b c))]
          (recur (inc i)
                 (u32+ t1 t2) a b c
                 (u32+ d t1) e f g))))))

(defn- pad
  "Pad a message so its length is a multiple of 64 bytes (0x80, zeros, 64-bit BE bit length)."
  [msg]
  (let [mlen (alength msg)
        k (mod (- 56 (+ mlen 1)) 64)
        total (+ mlen 1 k 8)
        out (byte-array total)
        bitlen (* 8 mlen)]
    (dotimes [i mlen] (aset out i (aget msg i)))
    (aset out mlen (unchecked-byte 0x80))
    (dotimes [i 8]
      (aset out (+ mlen 1 k i)
            (unchecked-byte (bit-and (unsigned-bit-shift-right bitlen (* 8 (- 7 i))) 0xFF))))
    out))

(defn digest
  "SHA-256 digest of a byte array, as a 32-byte byte array."
  [msg]
  (let [padded (pad msg)
        nblocks (quot (alength padded) 64)]
    (loop [i 0 hs h0]
      (if (= i nblocks)
        (let [out (byte-array 32)]
          (doseq [wi (range 8)]
            (let [h (nth hs wi), j (* 4 wi)]
              (aset out j (unchecked-byte (bit-and (unsigned-bit-shift-right h 24) 0xFF)))
              (aset out (inc j) (unchecked-byte (bit-and (unsigned-bit-shift-right h 16) 0xFF)))
              (aset out (+ 2 j) (unchecked-byte (bit-and (unsigned-bit-shift-right h 8) 0xFF)))
              (aset out (+ 3 j) (unchecked-byte (bit-and h 0xFF)))))
          out)
        (recur (inc i) (compress-block hs padded (* 64 i)))))))

(def ^:private hex-chars "0123456789abcdef")

(defn hex
  "Lowercase hex encoding of a byte array."
  [bytes]
  (apply str
         (mapcat (fn [b]
                   (let [b (bit-and b 0xFF)]
                     [(nth hex-chars (bit-shift-right b 4))
                      (nth hex-chars (bit-and b 0xF))]))
                 bytes)))

(defn hex-digest
  "Lowercase hex string of the SHA-256 digest of a byte array."
  [bytes]
  (hex (digest bytes)))
