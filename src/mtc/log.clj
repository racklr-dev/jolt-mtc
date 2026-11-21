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
  (:require [jolt.merkle :as m]
            [jolt.subtree :as st]))

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

(defn save-log
  "Persist a log's entries to a file: [4-byte big-endian length][entry]..."
  [log path]
  (let [out (java.io.FileOutputStream. path)]
    (doseq [e (:entries log)]
      (let [len (alength e)]
        (dotimes [i 4]
          (.write out (bit-and (bit-shift-right len (* 8 (- 3 i))) 0xFF)))
        (.write out e)))
    (.close out))
  log)

(defn load-log
  "Load a log from a file written by save-log, rebuilding the Merkle tree head."
  [number path]
  (let [bs (try (.readAllBytes (java.io.FileInputStream. path))
                (catch Throwable _ nil))]
    (if (or (nil? bs) (zero? (alength bs)))
      (new-log number)
      (loop [off 0 acc (new-log number)]
        (if (>= off (alength bs))
          acc
          (let [len (loop [i 0 n 0]
                      (if (= i 4) n (recur (inc i) (+ (* n 256) (bit-and (aget bs (+ off i)) 0xFF)))))
                entry (byte-array (map (fn [i] (aget bs (+ off 4 i))) (range len)))]
            (recur (+ off 4 len) (append! acc entry))))))))

(defn consistency-proof [log start end]
  (st/subtree-proof-tbl (node-table log) start end (tree-size log)))
