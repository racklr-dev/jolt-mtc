;; Minimal X.509 DER codec: Name, Validity, AlgorithmIdentifier.
(ns mtc.x509
  "Minimal X.509 DER codec for the fields MTC needs.

  A Name is a SEQUENCE of RDNs; each RDN is a SET of AttributeTypeAndValue;
  each ATV is a SEQUENCE of {OID, value}.  Values are DER string types
  (:utf8 :printable :ia5).  Validity is a SEQUENCE of two Time values
  (:utc or :gentime).  AlgorithmIdentifier is a SEQUENCE of {OID, params}.

  Full RFC5280 name/value surface is out of scope — enough to build and
  parse the structured names and validity a test CA and relying party use."
  (:require [mtc.der :as der]))

;; --- Name -------------------------------------------------------------------
;; A Name is a vector of RDNs.  An RDN is a vector of [oid value] pairs.

(defn encode-name
  "Encode a Name from a vector of RDNs (each a vector of [oid value])."
  [rdns]
  (der/encode
    (into [:seq]
          (map (fn [rdn]
                 (into [:set]
                       (map (fn [[oid value]] [:seq [:oid oid] value]) rdn)))
               rdns))))

(defn decode-name
  "Decode a DER Name into a vector of RDNs (each a vector of [oid value])."
  [bytes]
  (let [[v _] (der/decode bytes)]
    (when-not (= :seq (first v))
      (throw (ex-info "Name must be a SEQUENCE" {})))
    (mapv (fn [rdn]
            (when-not (= :set (first rdn))
              (throw (ex-info "RDN must be a SET" {})))
            (mapv (fn [atv]
                    (when-not (= :seq (first atv))
                      (throw (ex-info "ATV must be a SEQUENCE" {})))
                    (let [oid-v (second atv)
                          value (nth atv 2)]
                      (when-not (= :oid (first oid-v))
                        (throw (ex-info "ATV type must be an OID" {})))
                      [(second oid-v) value]))
                  (rest rdn)))
          (rest v))))

;; --- Validity ---------------------------------------------------------------

(defn encode-validity
  "Encode a Validity from two Time values, each [:utc s] or [:gentime s]."
  [not-before not-after]
  (der/encode [:seq not-before not-after]))

(defn decode-validity
  "Decode a DER Validity into [not-before not-after] Time values."
  [bytes]
  (let [[v _] (der/decode bytes)]
    (when-not (= :seq (first v))
      (throw (ex-info "Validity must be a SEQUENCE" {})))
    [(second v) (nth v 2)]))

;; --- AlgorithmIdentifier ----------------------------------------------------

(defn encode-alg-id
  "Encode an AlgorithmIdentifier from OID arcs and a params DER value
  (nil -> NULL)."
  [oid-arcs params]
  (der/encode [:seq [:oid oid-arcs] (or params [:null])]))

(defn decode-alg-id
  "Decode a DER AlgorithmIdentifier into [oid-arcs params]."
  [bytes]
  (let [[v _] (der/decode bytes)]
    (when-not (= :seq (first v))
      (throw (ex-info "AlgorithmIdentifier must be a SEQUENCE" {})))
    (let [oid-v (second v)
          params (nth v 2)]
      (when-not (= :oid (first oid-v))
        (throw (ex-info "AlgorithmIdentifier algorithm must be an OID" {})))
      [(second oid-v) params])))
