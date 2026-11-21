;; RFC 4.5 — efficiently covering an arbitrary interval with two subtrees.
(ns mtc.covering
  "RFC Section 4.5: Efficiently Covering Arbitrary Intervals.

  Not every [start, end) is a valid subtree, and the smallest single
  subtree containing it can be the whole tree.  Two subtrees are always
  sufficient and each is at most BIT_CEIL(end - start) in size.  This is
  how the CA signs the entries added since the last checkpoint, and how
  landmark subtrees (RFC 6.4.1) are derived.

  This is a direct port of the RFC's Python reference (4.5.1), with all
  arithmetic kept in uint64 (Long) space."
  (:require [mtc.bit :as bit]))

(defn find-subtrees
  "Given any [start, end) (unsigned 64-bit values), return the pair
  [[left-start mid] [mid end]] of two subtrees that efficiently cover it
  (RFC 4.5.1)."
  [start end]
  (let [start (bit/u64 start)
        end (bit/u64 end)
        size (unchecked-subtract end start)]
    (if (bit/u64-<= size 1)
      [[start end] [end end]]
      (let [last (unchecked-subtract end 1)
            split (dec (bit/bit-width (bit-xor start last)))
            mask (unchecked-subtract (bit-shift-left 1 split) 1)
            mid (bit-and last (bit-not mask))
            left-split (bit/bit-width (bit-and (bit-not start) mask))
            left-start (bit-and start (bit-not (unchecked-subtract (bit-shift-left 1 left-split) 1)))]
        [[left-start mid] [mid end]]))))
