;; RFC 7.3 — relying-party cosigner policies.
(ns mtc.policy
  "Cosigner policies (RFC Section 7.3). A policy is a predicate over the set of
  cosigner IDs whose signatures on a subtree are valid: (fn [valid-ids] -> bool).
  Quorums are the mechanism a relying party uses to require both the CA
  cosigner (authenticity) and additional witness/mirror cosigners (transparency)."
  (:require [clojure.set :as set]))

(defn any-of
  "Accept if at least one of `ids` signed."
  [ids]
  (let [ids (set ids)]
    (fn [valid] (boolean (some ids valid)))))

(defn all-of
  "Accept only if every one of `ids` signed."
  [ids]
  (let [ids (set ids)]
    (fn [valid] (every? ids valid))))

(defn ca-and-n-of
  "Accept when the CA cosigner signed AND at least `n` of `witness-ids` signed.
  This is the RFC 7.3 authenticity + transparency quorum shape."
  [ca-id witness-ids n]
  (let [witnesses (set witness-ids)]
    (fn [valid]
      (let [v (set valid)]
        (and (contains? v ca-id)
             (>= (count (set/intersection v witnesses)) n))))))
