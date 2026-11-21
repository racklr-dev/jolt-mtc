;; RFC 6.4 — landmark sequences and landmark-relative certificates.
(ns mtc.landmarks
  "RFC Section 6.4: Landmarks.

  A landmark sequence is append-only; landmark 0 is {tree-size 0, expiry 0}.
  Each later landmark has strictly increasing tree size and non-decreasing
  expiry.  The two landmark subtrees for landmark L are the two subtrees
  covering [prev_tree_size, tree_size) (jolt.covering).  An unexpired
  landmark is active; active landmark subtrees are predistributed.

  The publish format (RFC 6.4.3) is strict: a header line (latest_landmark
  decimal), then one line per listed landmark of '<tree_size> <expiry>'
  (decimal, single space, newline), tree sizes strictly decreasing,
  expiries monotonically decreasing, at least one expired landmark."
  (:require [clojure.string :as str]
            [jolt.covering :as cov]
            [jolt.merkle :as m]))

(defn allocate-landmark
  "Append a landmark with the next number to the sequence."
  [landmarks tree-size expiry]
  (conj landmarks {:number (count landmarks) :tree-size tree-size :expiry expiry}))

(defn landmark-subtrees
  "The two landmark subtrees for landmark number L."
  [landmarks L]
  (if (zero? L)
    [[0 0] [0 0]]
    (let [cur (nth landmarks L)
          prev (nth landmarks (dec L))]
      (cov/find-subtrees (:tree-size prev) (:tree-size cur)))))

(defn active-landmarks
  "Landmarks (number >= 1) whose expiry is after now."
  [landmarks now]
  (filter (fn [l] (and (pos? (:number l)) (> (:expiry l) now))) landmarks))

(defn- parse-decimal
  "Strict decimal integer: all digits, no leading zero (except \"0\")."
  [s]
  (when (and (seq s)
             (every? (fn [c] (<= (int \0) (int c) (int \9))) s)
             (or (= 1 (count s)) (not= \0 (first s))))
    (reduce (fn [acc c] (+ (* acc 10) (- (int c) (int \0)))) 0 s)))

(defn encode-landmarks
  "Publish a landmark sequence (RFC 6.4.3). Lists the active landmarks plus
  the first expired one, newest first."
  [landmarks now]
  (let [latest (dec (count landmarks))
        num-active (count (active-landmarks landmarks now))
        lines (map (fn [i]
                     (let [l (nth landmarks (- latest i))]
                       (str (:tree-size l) " " (:expiry l))))
                   (range (inc num-active)))]
    (str latest "\n" (str/join "\n" lines) "\n")))

(defn landmark-for-index
  "The lowest-numbered landmark whose tree size is strictly greater than idx
  (RFC 6.4.4)."
  [landmarks idx]
  (first (filter (fn [l] (> (:tree-size l) idx)) landmarks)))

(defn landmark-subtree-for-index
  "The landmark subtree of the covering landmark for idx, as [start end)."
  [landmarks idx]
  (when-let [L (landmark-for-index landmarks idx)]
    (let [[left right] (landmark-subtrees landmarks (:number L))]
      (or (when (<= (first left) idx (dec (second left))) left)
          (when (<= (first right) idx (dec (second right))) right)))))

(defn landmark-relative-proof
  "Build the landmark-relative MTCProof for entry idx (RFC 6.4.4): the proof
  for the covering landmark subtree, with no cosignatures."
  [entries landmarks idx extensions]
  (when-let [[s e] (landmark-subtree-for-index landmarks idx)]
    (let [nt (m/node-table entries)
          proof (m/inclusion-path-tbl nt (- idx s) s e)]
      {:extensions extensions :start s :end e :inclusion-proof proof :signatures []})))

(defn decode-landmarks
  "Strictly decode a published landmark document. Returns a vector of
  {:number :tree-size :expiry} for the listed landmarks (newest first).
  Throws on any deviation from RFC 6.4.3."
  [text now]
  (let [parts (str/split text #"\n" -1)]
    (when-not (= "" (last parts))
      (throw (ex-info "landmark document must end with a newline" {})))
    (let [lines (vec (butlast parts))]
      (when (empty? lines)
        (throw (ex-info "empty landmark document" {})))
      (let [latest (parse-decimal (first lines))]
        (when (or (nil? latest) (> latest 281474976710655))
          (throw (ex-info "bad latest_landmark" {:v (first lines)})))
        (let [body (rest lines)]
          (when (> (count body) (inc latest))
            (throw (ex-info "too many landmark lines" {})))
          (let [listed
                (loop [i 0 acc [] prev-tree nil prev-expiry nil]
                  (if (>= i (count body))
                    acc
                    (let [fields (str/split (nth body i) #" " -1)]
                      (when-not (= 2 (count fields))
                        (throw (ex-info "landmark line must be 'tree_size expiry'"
                                        {:line (nth body i)})))
                      (let [tree-size (parse-decimal (nth fields 0))
                            expiry (parse-decimal (nth fields 1))]
                        (when (or (nil? tree-size) (nil? expiry) (> tree-size 281474976710655))
                          (throw (ex-info "bad landmark values" {:line (nth body i)})))
                        (when (and prev-tree (not (< tree-size prev-tree)))
                          (throw (ex-info "tree sizes not strictly decreasing" {})))
                        (when (and prev-expiry (not (<= expiry prev-expiry)))
                          (throw (ex-info "expiries not monotonically decreasing" {})))
                        (recur (inc i)
                               (conj acc {:number (- latest i)
                                          :tree-size tree-size
                                          :expiry expiry})
                               tree-size expiry)))))]
            (when-not (some (fn [l] (< (:expiry l) now)) listed)
              (throw (ex-info "no expired landmark" {})))
            listed))))))
