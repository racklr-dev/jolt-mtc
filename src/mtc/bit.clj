;; RFC 2 (Conventions and Definitions) bit/integer primitives.
;; The whole subtree algorithm in RFC 4 is expressed over these four ops.
(ns mtc.bit
  "Bit and integer primitives from RFC 2.

  The subtree procedures are written in terms of four operations on
  non-negative integers:

    LSB(n)        least-significant bit of n  (n mod 2)
    BIT_WIDTH(n)  smallest number of bits needed to represent n;
                  BIT_WIDTH(0) is 0
    POPCOUNT(n)   number of set bits in n
    BIT_CEIL(n)   smallest power of 2 greater than or equal to n

  jolt bit ops (bit-and/-or/-xor/-not, shifts) operate on 64-bit Longs
  only — not BigInt.  Protocol tree sizes are uint48 (<= 2^48-1), but
  Appendix C.2 tests up to 2^64-1, so this namespace treats a Long as
  an unsigned 64-bit value (two's complement) and provides u64 / low-mask
  / u64-<= to keep those values inside Long arithmetic.")

(defn lsb
  "Least-significant bit of n: (bit-and n 1)."
  [n]
  (bit-and n 1))

(defn bit-width
  "Smallest number of bits needed to represent n; 0 for n=0.  A negative
  Long is read as a uint64 with its top bit set, so its width is 64."
  [n]
  (cond
    (zero? n) 0
    (neg? n) 64
    :else (loop [n n, w 0]
            (if (zero? n) w (recur (bit-shift-right n 1) (inc w))))))

(defn popcount
  "Number of set bits in n (Brian Kernighan's method)."
  [n]
  (loop [n n, c 0]
    (if (zero? n)
      c
      (recur (bit-and n (dec n)) (inc c)))))

(defn bit-ceil
  "Smallest power of 2 greater than or equal to n; 1 for n=0."
  [n]
  (if (<= n 1)
    1
    (bit-shift-left 1 (bit-width (dec n)))))

(defn rotate-right32
  "Rotate a 32-bit word right by k bits (0 <= k < 32)."
  [x k]
  (let [x (bit-and x 0xFFFFFFFF)
        k (mod k 32)]
    (bit-and 0xFFFFFFFF
             (bit-or (unsigned-bit-shift-right x k)
                     (bit-shift-left x (- 32 k))))))

(defn rotate-left32
  "Rotate a 32-bit word left by k bits (0 <= k < 32)."
  [x k]
  (rotate-right32 x (- 32 (mod k 32))))

;; --- uint64 helpers (values as Longs, two's complement) ---------------------

(def uint64-sign-bit
  "2^63 as a Long (Long/MIN_VALUE)."
  (bit-shift-left 1 63))

(defn u64
  "Coerce any integer to a Long interpreted as an unsigned 64-bit value."
  [x]
  (unchecked-long x))

(defn u64-<=
  "Unsigned 64-bit comparison a <= b, for a and b already Longs."
  [a b]
  (<= (bit-xor a uint64-sign-bit) (bit-xor b uint64-sign-bit)))

(defn low-mask
  "A Long whose low k bits (0 <= k <= 63) are set."
  [k]
  (if (zero? k)
    0
    (bit-not (bit-shift-left -1 k))))
