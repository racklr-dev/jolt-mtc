;; RFC 6.4 — landmark sequences and landmark-relative certificates.
(ns mtc.landmarks
  "RFC Section 6.4: Landmarks.

  A landmark sequence is append-only; landmark 0 is {tree-size 0,
  expiry 0}.  Each later landmark has strictly increasing tree size and
  non-decreasing expiry.  The two landmark subtrees for landmark L are
  the two subtrees covering [prev_tree_size, tree_size) (mtc.covering).
  An unexpired landmark is active; active landmark subtrees are
  predistributed to relying parties.

  The publish format (RFC 6.4.3) is a strict text format: a header line
  (latest_landmark decimal) then one line per active landmark of
  '<tree_size> <expiry>' (decimal, single space, newline), tree sizes
  strictly decreasing, at least one expired landmark.  Decoders must
  reject any deviation.")

;; (defn landmark-subtrees [landmarks L] ...)  ; -> [left right] covering [prev, current)
;; (defn allocate-landmark [log now max-cert-lifetime] ...)
;; (defn encode-landmarks [landmarks] ...)     ; strict publish format
;; (defn decode-landmarks [text] ...)          ; strict decoder
