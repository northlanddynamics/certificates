package keystore

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"unicode"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// Go's X.509 package can neither make an ML-DSA CSR, encode an ML-DSA key nor give an ML-DSA Certificate's public key, so
// these are made here from Cloudflare's CIRCL and Go's ASN.1 encoder, in the shapes RFC 9881 gives (the Go standard
// library's ML-DSA package, when the Agent moves to a Go that has it, may replace CIRCL's; the CSR stays as it is).

const seedSize = 32

// mlDsaParameterSet is what makes the keys of one ML-DSA parameter set: the RFC 9881 OID, and from a seed, the raw public key and a signer.
type mlDsaParameterSet struct {
	oid    asn1.ObjectIdentifier
	derive func(seed *[seedSize]byte) (publicKey []byte, sign func(message []byte) ([]byte, error))
}

var mlDsaAlgorithms = map[string]mlDsaParameterSet{
	"ml-dsa-44": {asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}, func(seed *[seedSize]byte) ([]byte, func([]byte) ([]byte, error)) {
		pk, sk := mldsa44.NewKeyFromSeed(seed)
		return pk.Bytes(), func(message []byte) ([]byte, error) {
			sig := make([]byte, mldsa44.SignatureSize)
			return sig, mldsa44.SignTo(sk, message, nil, true, sig)
		}
	}},
	"ml-dsa-65": {asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, func(seed *[seedSize]byte) ([]byte, func([]byte) ([]byte, error)) {
		pk, sk := mldsa65.NewKeyFromSeed(seed)
		return pk.Bytes(), func(message []byte) ([]byte, error) {
			sig := make([]byte, mldsa65.SignatureSize)
			return sig, mldsa65.SignTo(sk, message, nil, true, sig)
		}
	}},
	"ml-dsa-87": {asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}, func(seed *[seedSize]byte) ([]byte, func([]byte) ([]byte, error)) {
		pk, sk := mldsa87.NewKeyFromSeed(seed)
		return pk.Bytes(), func(message []byte) ([]byte, error) {
			sig := make([]byte, mldsa87.SignatureSize)
			return sig, mldsa87.SignTo(sk, message, nil, true, sig)
		}
	}},
}

var (
	oidExtensionRequest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	oidSubjectAltName     = asn1.ObjectIdentifier{2, 5, 29, 17}
	dNSNameTag            = 2
	seedPrivateKeyPrefix  = []byte{0x80, seedSize} // [0] IMPLICIT OCTET STRING of 32 bytes
	errNameIsNotIA5String = errors.New("a name that is not ASCII cannot be in a CSR's subject alternative names")
)

// generateMLDSA makes a key of the parameter set from a random seed.
func generateMLDSA(params mlDsaParameterSet) (material, error) {
	var seed [seedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return material{}, err
	}
	publicKey, sign := params.derive(&seed)
	algorithmIdentifier := pkix.AlgorithmIdentifier{Algorithm: params.oid} // parameters absent, for keys and signatures alike

	// RFC 9881's seed form of PKCS#8, which OpenSSL 3.5 and Bun read: the privateKey is `[0] IMPLICIT OCTET STRING` of the seed.
	pkcs8, err := asn1.Marshal(struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{0, algorithmIdentifier, append(append([]byte{}, seedPrivateKeyPrefix...), seed[:]...)})
	if err != nil {
		return material{}, err
	}
	spki, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{algorithmIdentifier, asn1.BitString{Bytes: publicKey, BitLength: 8 * len(publicKey)}})
	if err != nil {
		return material{}, err
	}
	return material{pkcs8: pkcs8, spki: spki, csr: func(names []string) ([]byte, error) {
		return mlDsaCSR(algorithmIdentifier, spki, names, sign)
	}}, nil
}

// mlDsaCSR is a PKCS#10 for the key whose SubjectPublicKeyInfo is spki: the first name as the common name, and all of the
// names in a subject alternative name extension, signed with randomized pure ML-DSA and an empty context.
func mlDsaCSR(algorithm pkix.AlgorithmIdentifier, spki []byte, names []string, sign func([]byte) ([]byte, error)) ([]byte, error) {
	generalNames := make([]asn1.RawValue, len(names))
	for i, name := range names {
		for _, r := range name {
			if r > unicode.MaxASCII {
				return nil, errNameIsNotIA5String
			}
		}
		generalNames[i] = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: dNSNameTag, Bytes: []byte(name)}
	}
	alternativeNames, err := asn1.Marshal(generalNames)
	if err != nil {
		return nil, err
	}
	// The attribute's value is a SET holding one Extensions, which is itself a SEQUENCE of Extension: leaving out that
	// inner SEQUENCE is accepted by some parsers and loses the names in Go's.
	extensions, err := asn1.Marshal([]pkix.Extension{{Id: oidSubjectAltName, Value: alternativeNames}})
	if err != nil {
		return nil, err
	}
	attribute, err := asn1.Marshal(struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue
	}{oidExtensionRequest, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: extensions}})
	if err != nil {
		return nil, err
	}
	subject, err := asn1.Marshal(pkix.Name{CommonName: names[0]}.ToRDNSequence())
	if err != nil {
		return nil, err
	}
	info, err := asn1.Marshal(struct {
		Version    int
		Subject    asn1.RawValue
		PublicKey  asn1.RawValue
		Attributes asn1.RawValue
	}{0, asn1.RawValue{FullBytes: subject}, asn1.RawValue{FullBytes: spki}, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attribute}})
	if err != nil {
		return nil, err
	}
	signature, err := sign(info)
	if err != nil {
		return nil, fmt.Errorf("signing the CSR: %w", err)
	}
	return asn1.Marshal(struct {
		Info      asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: info}, algorithm, asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)}})
}
