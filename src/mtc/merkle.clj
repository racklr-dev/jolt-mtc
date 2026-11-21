;; RFC9162 Merkle Tree Hash (MTH) — the tree the RFC's subtrees build over.
(ns mtc.merkle
  "RFC9162 Merkle Tree Hash, Section 2.1.1.

  MTC subtrees (RFC 4) are 'a Merkle Tree over an interval of entries
  from the original tree', so the base construction is RFC9162's MTH.
  Given a collision-resistant hash HASH (SHA-256 here):

    empty-hash            = HASH()
    leaf-hash d           = HASH(0x00 || d)
    node-hash left right  = HASH(0x01 || left || right)

  MTH(D_n) over D_n = {d[0]...d[n-1]}:
    MTH({})     = empty-hash
    MTH({d[0]}) = leaf-hash d[0]
    MTH(D_n)    = node-hash (MTH(D[0:k])) (MTH(D[k:n]))
                  where k is the largest power of two less than n

  For proof GENERATION at CA side, build a node-table once with
  node-table and use mth / inclusion-path-tbl / (mtc.subtree)
  subtree-proof-tbl — those are O(log n) per query instead of
  re-hashing the same subtrees."
  (:require [mtc.bit :as bit]
            [mtc.sha256 :as sha]))

(defn- concat-bytes
  "Concatenate byte arrays and/or single byte numbers into one byte array."
  [& parts]
  (let [parts (mapv (fn [p] (if (number? p) (byte-array [(unchecked-byte p)]) p)) parts)
        total (reduce + 0 (map alength parts))
        out (byte-array total)]
    (loop [off 0 ps (seq parts)]
      (when-let [p (first ps)]
        (dotimes [i (alength p)] (aset out (+ off i) (aget p i)))
        (recur (+ off (alength p)) (next ps))))
    out))

(defn empty-hash
  "HASH() — SHA-256 of the empty string."
  []
  (sha/digest (byte-array 0)))

(defn leaf-hash
  "HASH(0x00 || d) — the hash of a leaf entry d (a byte array)."
  [d]
  (sha/digest (concat-bytes 0x00 d)))

(defn node-hash
  "HASH(0x01 || left || right) — the hash of an interior node."
  [left right]
  (sha/digest (concat-bytes 0x01 left right)))

(defn bytes=
  "Element-wise byte-array equality (Clojure = is identity for arrays)."
  [a b]
  (= (vec a) (vec b)))

(defn largest-power-of-two-less-than
  "k = the largest power of two less than n (n > 1)."
  [n]
  (bit-shift-left 1 (dec (bit/bit-width (dec n)))))

(defn merkle-tree-hash
  "MTH over entries (a vector of byte arrays): the RFC9162 Merkle Tree Hash.
  Naive recursive form — correct, but O(n) hashes per call; use node-table + mth
  when querying many subtrees of the same tree."
  [entries]
  (let [n (count entries)]
    (cond
      (zero? n) (empty-hash)
      (= 1 n) (leaf-hash (first entries))
      :else
      (let [k (largest-power-of-two-less-than n)]
        (node-hash (merkle-tree-hash (subvec entries 0 k))
                   (merkle-tree-hash (subvec entries k)))))))

(defn node-table
  "Build a map [start end] -> hash of every node of the Merkle tree over
  entries. O(n) hashes to build; O(1) lookups afterwards. Leaf nodes (size 1)
  and every interior node of the tree are present."
  [entries]
  (letfn [(walk [tbl s e]
            (let [size (- e s)]
              (cond
                (zero? size) [tbl (empty-hash)]
                (= 1 size) (let [h (leaf-hash (nth entries s))]
                             [(assoc tbl [s e] h) h])
                :else (let [k (largest-power-of-two-less-than size)
                            [tbl hl] (walk tbl s (+ s k))
                            [tbl hr] (walk tbl (+ s k) e)
                            h (node-hash hl hr)]
                        [(assoc tbl [s e] h) h]))))]
    (first (walk {} 0 (count entries)))))

(defn mth
  "MTH(D[s:e]) for any interval within the tree whose node-table is tbl.
  O(log n) — combines full-subtree node hashes from the table, recursing only
  on the right-side remainder (which is how the RFC MTH recursion decomposes)."
  [tbl s e]
  (let [size (- e s)]
    (cond
      (zero? size) (empty-hash)
      (= 1 size) (get tbl [s e])
      (contains? tbl [s e]) (get tbl [s e])
      :else (let [k (largest-power-of-two-less-than size)]
              (node-hash (get tbl [s (+ s k)])
                         (mth tbl (+ s k) e))))))

(defn inclusion-path
  "RFC9162 PATH(m, D_n): the inclusion proof for leaf m in entries (naive
  recursive form, O(n) hashes per call). Prefer inclusion-path-tbl."
  [m entries]
  (let [n (count entries)]
    (if (<= n 1)
      []
      (let [k (largest-power-of-two-less-than n)]
        (if (< m k)
          (conj (inclusion-path m (subvec entries 0 k))
                (merkle-tree-hash (subvec entries k n)))
          (conj (inclusion-path (- m k) (subvec entries k n))
                (merkle-tree-hash (subvec entries 0 k))))))))

(defn inclusion-path-tbl
  "PATH(m, D[s:e]) using a node-table: the inclusion proof for relative leaf
  index m within the interval [s, e). O(log n) hashes per call."
  [tbl m s e]
  (let [size (- e s)]
    (if (<= size 1)
      []
      (let [k (largest-power-of-two-less-than size)]
        (if (< m k)
          (conj (inclusion-path-tbl tbl m s (+ s k)) (mth tbl (+ s k) e))
          (conj (inclusion-path-tbl tbl (- m k) (+ s k) e) (mth tbl s (+ s k))))))))
