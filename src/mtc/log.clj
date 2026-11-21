;; RFC 5.2 — the issuance log (append-only Merkle Tree over entries).
(ns mtc.log
  "RFC Section 5.2: Issuance Logs.

  A CA operates a series of issuance logs numbered 1..2^16-1; exactly one
  is current at a time.  Each log is an append-only sequence of at most
  2^48-1 entries, represented as a RFC9162 Merkle Tree.  A snapshot is a
  checkpoint identified by its tree size; its contents are MTH(D[0:size]).

  This namespace is the in-memory log for tests and a CA reference
  implementation: append entries, compute the root hash, serve subtree
  hashes and proofs by index.")

;; State shape: {:number 1 :entries [byte-array ...] :tree-size n}
;; (defn new-log [number] ...)
;; (defn append! [log entry] ...)            ; grow tree, return new size
;; (defn tree-size [log] ...)
;; (defn checkpoint [log] ...)               ; {:size n :hash MTH}
;; (defn entry-index->subtree ...)           ; locate an entry in a chosen subtree
