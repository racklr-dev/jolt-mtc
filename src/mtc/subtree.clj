;; RFC 4 — Subtrees: validity, hashing, inclusion proofs, consistency proofs.
(ns mtc.subtree
  "RFC Section 4: Subtrees.

  A subtree [start, end) is MTH(D[start:end]) subject to an alignment
  constraint (RFC 4.1):

    0 <= start <= end <= n,  and
    start is a multiple of BIT_CEIL(end - start)

  With the RFC's fixed-width overflow guard: if end - start exceeds
  2^63, the interval is valid iff start is 0.

  Public surface:
    valid-subtree? [start end]
    subtree-hash  [start end entries]
    inclusion-proof   [start end entries index]          ; generate (CA side)
    evaluate-inclusion-proof [start end index entry-hash proof]
    verify-inclusion-proof   [start end index entry-hash subtree-hash proof]
    consistency-proof       [start end entries]          ; generate (CA side)
    verify-consistency-proof [start end n node-hash root-hash proof]
    subtree-proof-tbl       [tbl start end n]            ; O(log n) generator"
  (:require [mtc.bit :as bit]
            [mtc.merkle :as m]))

(defn valid-subtree?
  "True when [start, end) satisfies RFC 4.1's subtree alignment constraint.
  start/end are unsigned 64-bit values; the RFC's fixed-width overflow guard
  (size > 2^63 => start must be 0) is preserved."
  [start end]
  (let [start (bit/u64 start)
        end (bit/u64 end)]
    (if (bit/u64-<= start end)
      (let [size (unchecked-subtract end start)]
        (if (and (neg? size) (not= size bit/uint64-sign-bit))  ; size > 2^63
          (zero? start)
          (let [k (if (zero? size) 0 (bit/bit-width (unchecked-subtract size 1)))]
            (zero? (bit-and start (bit/low-mask k))))))
      false)))

(defn subtree-hash
  "MTH(D[start:end]) — the hash of subtree [start, end)."
  [start end entries]
  (m/merkle-tree-hash (subvec entries start end)))

(defn inclusion-proof
  "The subtree inclusion proof (RFC 4.3) for entry `index` of [start, end):
  PATH(index - start, D[start:end]). Returns a vector of sibling hashes."
  [start end entries index]
  (m/inclusion-path (- index start) (subvec entries start end)))

(defn subtree-proof-tbl
  "RFC 4.4 SUBTREE_PROOF(start, end, D_n) using a node-table over the full
  tree: the subtree consistency proof for [start, end) in a tree of n entries."
  [tbl start end n]
  (if (= start end)
    []
    (letfn [(sub [base start end n b]
              ;; Tree is D[base : base+n]; [start, end) is absolute within it.
              (if (and (= start base) (= end (+ base n)))
                (if b [] [(m/mth tbl base (+ base n))])
                (let [k (m/largest-power-of-two-less-than n)
                      lk (+ base k)]
                  (cond
                    ;; subtree entirely in the left child [base, base+k)
                    (<= end lk)
                    (conj (sub base start end k b) (m/mth tbl lk (+ base n)))

                    ;; subtree entirely in the right child [base+k, base+n)
                    (>= start lk)
                    (conj (sub lk start end (- n k) b) (m/mth tbl base lk))

                    ;; start < base+k < end, which implies start = base
                    :else
                    (conj (sub lk lk end (- n k) false) (m/mth tbl base lk))))))]
      (sub 0 start end n true))))

(defn evaluate-inclusion-proof
  "RFC 4.3.2: evaluate a subtree inclusion proof to the expected subtree hash.
  `entry-hash` is HASH(0x00 || d[index]). Throws on any proof failure."
  [start end index entry-hash proof]
  (when-not (valid-subtree? start end)
    (throw (ex-info "invalid subtree" {:start start :end end})))
  (when-not (<= start index (dec end))
    (throw (ex-info "index outside subtree" {:start start :end end :index index})))
  (let [fn0 (- index start)
        sn0 (- end start 1)]
    (loop [fn fn0, sn sn0, r entry-hash, ps (seq proof)]
      (if (empty? ps)
        (if (zero? sn)
          r
          (throw (ex-info "inclusion proof too short" {:fn fn :sn sn})))
        (if (zero? sn)
          (throw (ex-info "inclusion proof too long" {:fn fn :sn sn}))
          (let [[fn sn r] (if (or (= 1 (bit/lsb fn)) (= fn sn))
                            (let [r (m/node-hash (first ps) r)]
                              (loop [fn fn, sn sn]
                                (if (= 1 (bit/lsb fn))
                                  [fn sn r]
                                  (recur (bit-shift-right fn 1) (bit-shift-right sn 1)))))
                            [fn sn (m/node-hash r (first ps))])]
            (recur (bit-shift-right fn 1) (bit-shift-right sn 1) r (next ps))))))))

(defn verify-inclusion-proof
  "RFC 4.3.3: true iff evaluating the inclusion proof yields subtree-hash."
  [start end index entry-hash subtree-hash proof]
  (try
    (m/bytes= subtree-hash (evaluate-inclusion-proof start end index entry-hash proof))
    (catch Throwable _ false)))

(defn- subtree-subproof
  "RFC 4.4.1 SUBTREE_SUBPROOF(start, end, D_n, b). Naive recursive form."
  [start end entries b]
  (let [n (count entries)]
    (if (and (zero? start) (= end n))
      (if b [] [(m/merkle-tree-hash entries)])
      (let [k (m/largest-power-of-two-less-than n)]
        (cond
          (<= end k)
          (conj (subtree-subproof start end (subvec entries 0 k) b)
                (m/merkle-tree-hash (subvec entries k n)))

          (<= k start)
          (conj (subtree-subproof (- start k) (- end k) (subvec entries k n) b)
                (m/merkle-tree-hash (subvec entries 0 k)))

          :else
          (conj (subtree-subproof 0 (- end k) (subvec entries k n) false)
                (m/merkle-tree-hash (subvec entries 0 k))))))))

(defn consistency-proof
  "RFC 4.4 SUBTREE_PROOF(start, end, D_n): naive recursive form. Prefer
  subtree-proof-tbl when generating many proofs over the same tree."
  [start end entries]
  (if (= start end)
    []
    (subtree-subproof start end entries true)))

(defn verify-consistency-proof
  "RFC 4.4.3: verify a subtree consistency proof for [start, end) in a tree
  of n elements, given subtree hash node-hash and root hash root-hash.
  Returns true iff the proof is valid."
  [start end n node-hash root-hash proof]
  (try
    (when-not (valid-subtree? start end)
      (throw (ex-info "invalid subtree" {:start start :end end})))
    (when-not (<= end n)
      (throw (ex-info "end exceeds tree size" {:end end :n n})))
    (if (= start end)
      (and (empty? proof) (m/bytes= node-hash (m/empty-hash)))
      (let [fn (atom start)
            sn (atom (dec end))
            tn (atom (dec n))
            fr (atom nil)
            sr (atom nil)
            ps (atom (vec proof))]
        (if (= @sn @tn)
          (while (not= @fn @sn)
            (swap! fn bit-shift-right 1)
            (swap! sn bit-shift-right 1)
            (swap! tn bit-shift-right 1))
          (while (and (not= @fn @sn) (= 1 (bit/lsb @sn)))
            (swap! fn bit-shift-right 1)
            (swap! sn bit-shift-right 1)
            (swap! tn bit-shift-right 1)))
        (if (= @fn @sn)
          (do (reset! fr node-hash) (reset! sr node-hash))
          (do (when (empty? @ps)
                (throw (ex-info "consistency proof too short" {})))
              (let [c (first @ps)]
                (reset! fr c) (reset! sr c))
              (swap! ps subvec 1)))
        (doseq [c @ps]
          (when (zero? @tn)
            (throw (ex-info "consistency proof too long" {})))
          (if (or (= 1 (bit/lsb @sn)) (= @sn @tn))
            (do (when (< @fn @sn)
                  (reset! fr (m/node-hash c @fr)))
                (reset! sr (m/node-hash c @sr))
                (while (not= 1 (bit/lsb @sn))
                  (swap! fn bit-shift-right 1)
                  (swap! sn bit-shift-right 1)
                  (swap! tn bit-shift-right 1)))
            (reset! sr (m/node-hash @sr c)))
          (swap! fn bit-shift-right 1)
          (swap! sn bit-shift-right 1)
          (swap! tn bit-shift-right 1))
        (and (zero? @tn) (m/bytes= @fr node-hash) (m/bytes= @sr root-hash))))
    (catch Throwable _ false)))
