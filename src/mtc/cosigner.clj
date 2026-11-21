;; RFC 5.3 — CosignedSubtree (cosignature format).
(ns mtc.cosigner
  "RFC Section 5.3: Cosigners and the subtree signature format.

  A cosigner follows an append-only view of a log and signs subtrees.
  The signed structure (TLS presentation language):

    opaque HashValue[HASH_SIZE];
    struct {
        uint8 label[12] = \"subtree/v1\\n\\0\";   ; domain separation
        opaque cosigner_name<1..2^8-1>;
        uint64 timestamp;                       ; 0 => no time statement
        opaque log_origin<1..2^8-1>;
        uint64 start; uint64 end;
        HashValue subtree_hash;
    } CosignedSubtree;

  cosigner_name / log_origin encode a trust anchor ID as the ASCII
  string oid/1.3.6.1.4.1.<arcs...> (RFC 5.3.1).  Signatures are computed
  over the whole CosignedSubtree; the algorithm is fixed by the cosigner
  ID's key, and the timestamp MUST be 0 inside an MTCProof.")

;; (defn cosigner-name [cosigner-id] ...)     ; -> "oid/1.3.6.1.4.1." + arcs
;; (defn log-origin [log-id] ...)
;; (defn encode-cosigned-subtree [{:keys [cosigner-name timestamp log-origin start end subtree-hash]}] ...)
;; (defn sign-cosigned-subtree [sigalg private-key subtree] ...)
;; (defn verify-cosigned-subtree [sigalg public-key subtree signature] ...)
