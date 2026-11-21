;; RFC 5.2 — the issuance log (append-only Merkle Tree over entries).
(ns mtc.log
  "RFC Section 5.2: Issuance Logs.

  A CA operates a series of issuance logs numbered 1..2^16-1; exactly one
  is current at a time.  Each log is an append-only sequence of at most
  2^48-1 entries, represented as a RFC9162 Merkle Tree.  A snapshot is a
  checkpoint identified by its tree size; its contents are MTH(D[0:size]).

  This namespace is an in-memory append-only log: entries are byte arrays
  (encoded MTCLogEntry values), the Merkle tree head is updated
  incrementally (RFC6962-style frontier), and subtree proofs are derived
  from the entries on demand."
  (:require [mtc.merkle :as m]
            [mtc.subtree :as st]))

(defn new-log
  "A fresh issuance log with the given positive log number."
  [number]
  {:number number :entries [] :tree-size 0 :stack [] :root (m/empty-hash)})

(defn- fold-root [stack]
  (if (empty? stack)
    (m/empty-hash)
    (let [h0 (:hash (first stack))]
      (reduce (fn [r node] (m/node-hash r (:hash node))) h0 (rest stack)))))

(defn append!
  "Append an entry (a byte array) to the log; returns the updated log."
  [log entry]
  (let [leaf (m/leaf-hash entry)
        stack (loop [stack (:stack log) leaf leaf size 1]
                (if (and (seq stack) (= size (:size (peek stack))))
                  (let [top (peek stack)]
                    (recur (pop stack) (m/node-hash (:hash top) leaf) (* 2 size)))
                  (conj stack {:size size :hash leaf})))]
    (assoc log
           :entries (conj (:entries log) entry)
           :stack stack
           :tree-size (inc (:tree-size log))
           :root (fold-root stack))))

(defn tree-size [log] (:tree-size log))

(defn root-hash [log] (:root log))

(defn checkpoint [log]
  "A checkpoint of the current log state."
  {:size (tree-size log) :hash (root-hash log)})

(defn node-table [log]
  "The full Merkle node table over the log's entries."
  (m/node-table (:entries log)))

(defn subtree-hash [log start end]
  (m/mth (node-table log) start end))

(defn inclusion-proof [log start end index]
  (m/inclusion-path-tbl (node-table log) (- index start) start end))

(defn consistency-proof [log start end]
  (st/subtree-proof-tbl (node-table log) start end (tree-size log)))
