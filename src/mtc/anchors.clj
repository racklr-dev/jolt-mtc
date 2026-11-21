;; RFC 5.1 + Section 8 — trust anchor IDs and the TLS trust_anchors extension.
(ns mtc.anchors
  "Trust anchor IDs for Merkle Tree Certificates (RFC 5.1) and their use in
  TLS (RFC 8), per the trust-anchor-ids draft.

  A CA ID's OID arc is reserved: {caID logs(0) N} is issuance log N,
  {caID landmarks(1) N L} is landmark L of log N, and
  {caID landmarkGroups(2) N L} is the landmark group for log N through
  landmark L.  The trust_anchors TLS extension carries TrustAnchorID lists,
  whose contents are the RELATIVE-OID binary form of the ID."
  (:require [mtc.tls :as tls]
            [mtc.cosigner :as cos]))

(defn log-id
  "{caID logs(0) N} — the issuance log N trust anchor ID."
  [ca-id n]
  (conj (vec ca-id) 0 n))

(defn landmark-id
  "{caID landmarks(1) N L} — landmark L of log N."
  [ca-id n l]
  (conj (vec ca-id) 1 n l))

(defn landmark-group-id
  "{caID landmarkGroups(2) N L} — the landmark group for log N through L."
  [ca-id n l]
  (conj (vec ca-id) 2 n l))

(defn landmark-group-members
  "The trust anchor IDs in landmark group {caID landmarkGroups(2) N L}: the CA
  ID itself plus every landmark ID of log N from 0 through L (RFC 8.2.1)."
  [ca-id n l]
  (into [(vec ca-id)] (map (fn [m] (landmark-id ca-id n m)) (range (inc l)))))

(defn encode-trust-anchor-id
  "Encode one TrustAnchorID (TLS struct opaque<1..32>): a 1-byte length prefix
  followed by the ID's RELATIVE-OID binary contents."
  [arcs]
  (tls/varlen 1 (cos/cosigner-id-bytes arcs)))

(defn decode-trust-anchor-id
  "Decode a TrustAnchorID back to its PEN-relative arcs."
  [bytes]
  (let [[content _] (tls/read-varlen bytes 0 1)]
    (cos/cosigner-id-arcs content)))

(defn encode-requested-trust-anchor-list
  "Encode a RequestedTrustAnchorList (TLS): TrustAnchorID <0..2^16-1>."
  [ids]
  (tls/varlen 2 (apply tls/concat-bytes (map encode-trust-anchor-id ids))))

(defn encode-available-trust-anchor-list
  "Encode an AvailableTrustAnchorList (TLS): TrustAnchorID <1..2^16-1>."
  [ids]
  (tls/varlen 2 (apply tls/concat-bytes (map encode-trust-anchor-id ids))))

(defn decode-trust-anchor-id-list
  "Decode a RequestedTrustAnchorList / AvailableTrustAnchorList back into a
  vector of PEN-relative arc vectors."
  [bytes]
  (let [[content _] (tls/read-varlen bytes 0 2)]
    (loop [off 0 acc []]
      (if (>= off (alength content))
        acc
        (let [[id i] (tls/read-varlen content off 1)]
          (recur i (conj acc (cos/cosigner-id-arcs id))))))))
