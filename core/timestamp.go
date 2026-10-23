package core

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"
)

// RFC 3161 time-stamp tokens (spec/checkpoint.md §5), parsed and verified
// with the standard library only.

var (
	oidSignedData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidAttrContentType      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningCertificate   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidExtKeyUsage          = asn1.ObjectIdentifier{2, 5, 29, 37}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSA          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256RSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384RSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512RSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECPublicKey  = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidECDSASHA256  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSASHA384  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSASHA512  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	hashAlgorithms  = map[string]crypto.Hash{oidSHA256.String(): crypto.SHA256, oidSHA384.String(): crypto.SHA384, oidSHA512.String(): crypto.SHA512}
	rsaAlgorithms   = map[crypto.Hash]x509.SignatureAlgorithm{crypto.SHA256: x509.SHA256WithRSA, crypto.SHA384: x509.SHA384WithRSA, crypto.SHA512: x509.SHA512WithRSA}
	ecdsaAlgorithms = map[crypto.Hash]x509.SignatureAlgorithm{crypto.SHA256: x509.ECDSAWithSHA256, crypto.SHA384: x509.ECDSAWithSHA384, crypto.SHA512: x509.ECDSAWithSHA512}
)

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	Nonce          *big.Int `asn1:"optional"`
	CertReq        bool     `asn1:"optional"`
}

// TimestampRequest returns a DER-encoded RFC 3161 TimeStampReq for the
// SHA-256 hash of data, with a random nonce, asking the TSA to include its
// certificate. It also returns the nonce.
func TimestampRequest(data []byte) ([]byte, *big.Int, error) {
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, nil, err
	}
	h := crypto.SHA256.New()
	h.Write(data)
	req, err := asn1.Marshal(timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
			HashedMessage: h.Sum(nil),
		},
		Nonce:   nonce,
		CertReq: true,
	})
	return req, nonce, err
}

// Timestamp is a verified RFC 3161 time-stamp.
type Timestamp struct {
	Time   time.Time
	Policy asn1.ObjectIdentifier
	Serial *big.Int
	Nonce  *big.Int // nil if the request had none
	Signer *x509.Certificate
}

// VerifyTimestamp verifies an RFC 3161 time-stamp over data. tsr may be a
// TimeStampResp, as returned by a TSA, or a bare TimeStampToken. The TSA
// certificate must chain to roots (the system roots if roots is nil), be
// valid at the time of stamping and be restricted to time stamping.
func VerifyTimestamp(tsr, data []byte, roots *x509.CertPool) (*Timestamp, error) {
	token, err := extractToken(tsr)
	if err != nil {
		return nil, err
	}
	sd, err := parseSignedData(token)
	if err != nil {
		return nil, err
	}
	info, err := parseTSTInfo(sd.eContent)
	if err != nil {
		return nil, err
	}

	imprintHash, ok := hashAlgorithms[info.imprint.HashAlgorithm.Algorithm.String()]
	if !ok {
		return nil, fmt.Errorf("unsupported message imprint algorithm %v", info.imprint.HashAlgorithm.Algorithm)
	}
	h := imprintHash.New()
	h.Write(data)
	if !bytes.Equal(h.Sum(nil), info.imprint.HashedMessage) {
		return nil, errors.New("time-stamp is for different data")
	}

	signer, err := sd.verifySigner()
	if err != nil {
		return nil, err
	}
	if err := verifyTSACert(signer, sd.certs, roots, info.genTime); err != nil {
		return nil, err
	}
	return &Timestamp{Time: info.genTime, Policy: info.policy, Serial: info.serial, Nonce: info.nonce, Signer: signer}, nil
}

// elements returns the elements of a DER SEQUENCE or SET.
func elements(der []byte, tag int) ([]asn1.RawValue, error) {
	var outer asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &outer); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("trailing data")
	}
	if outer.Class != asn1.ClassUniversal || outer.Tag != tag || !outer.IsCompound {
		return nil, fmt.Errorf("expected universal tag %d, got class %d tag %d", tag, outer.Class, outer.Tag)
	}
	return contents(outer.Bytes)
}

// contents splits concatenated DER values.
func contents(b []byte) ([]asn1.RawValue, error) {
	var els []asn1.RawValue
	for len(b) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(b, &v)
		if err != nil {
			return nil, err
		}
		els = append(els, v)
		b = rest
	}
	return els, nil
}

func isContext(v asn1.RawValue, tag int) bool {
	return v.Class == asn1.ClassContextSpecific && v.Tag == tag
}

func unmarshalAll(der []byte, v any) error {
	rest, err := asn1.Unmarshal(der, v)
	if err == nil && len(rest) != 0 {
		err = errors.New("trailing data")
	}
	return err
}

// extractToken returns the TimeStampToken (a CMS ContentInfo) from a
// TimeStampResp, or tsr itself if it already is a token.
func extractToken(tsr []byte) ([]byte, error) {
	els, err := elements(tsr, asn1.TagSequence)
	if err != nil {
		return nil, fmt.Errorf("time-stamp: %w", err)
	}
	if len(els) > 0 && els[0].Tag == asn1.TagOID {
		return tsr, nil
	}
	if len(els) == 0 || len(els) > 2 {
		return nil, errors.New("malformed time-stamp response")
	}
	status, err := elements(els[0].FullBytes, asn1.TagSequence)
	if err != nil || len(status) == 0 {
		return nil, errors.New("malformed time-stamp status")
	}
	var code int
	if err := unmarshalAll(status[0].FullBytes, &code); err != nil {
		return nil, errors.New("malformed time-stamp status")
	}
	if code != 0 && code != 1 { // granted, grantedWithMods
		return nil, fmt.Errorf("time-stamp request was rejected (status %d)", code)
	}
	if len(els) != 2 {
		return nil, errors.New("time-stamp response has no token")
	}
	return els[1].FullBytes, nil
}

type signedData struct {
	digest      crypto.Hash
	eContent    []byte
	certs       []*x509.Certificate
	sid         asn1.RawValue
	signedAttrs asn1.RawValue
	sigAlg      asn1.ObjectIdentifier
	signature   []byte
}

func parseSignedData(token []byte) (*signedData, error) {
	ci, err := elements(token, asn1.TagSequence)
	if err != nil || len(ci) != 2 || !isContext(ci[1], 0) {
		return nil, errors.New("malformed time-stamp token")
	}
	var ct asn1.ObjectIdentifier
	if err := unmarshalAll(ci[0].FullBytes, &ct); err != nil || !ct.Equal(oidSignedData) {
		return nil, errors.New("time-stamp token is not CMS signed data")
	}
	sdEls, err := elements(ci[1].Bytes, asn1.TagSequence)
	if err != nil || len(sdEls) < 4 {
		return nil, errors.New("malformed signed data")
	}

	sd := &signedData{}
	encap, err := elements(sdEls[2].FullBytes, asn1.TagSequence)
	if err != nil || len(encap) != 2 || !isContext(encap[1], 0) {
		return nil, errors.New("malformed encapsulated content")
	}
	var ect asn1.ObjectIdentifier
	if err := unmarshalAll(encap[0].FullBytes, &ect); err != nil || !ect.Equal(oidTSTInfo) {
		return nil, errors.New("signed content is not a TSTInfo")
	}
	if err := unmarshalAll(encap[1].Bytes, &sd.eContent); err != nil {
		return nil, errors.New("malformed TSTInfo content")
	}

	rest := sdEls[3:]
	if isContext(rest[0], 0) {
		certEls, err := contents(rest[0].Bytes)
		if err != nil {
			return nil, errors.New("malformed certificates")
		}
		for _, c := range certEls {
			if c.Class == asn1.ClassUniversal && c.Tag == asn1.TagSequence {
				cert, err := x509.ParseCertificate(c.FullBytes)
				if err != nil {
					return nil, fmt.Errorf("certificate in token: %w", err)
				}
				sd.certs = append(sd.certs, cert)
			}
		}
		rest = rest[1:]
	}
	if len(rest) > 0 && isContext(rest[0], 1) { // CRLs
		rest = rest[1:]
	}
	if len(rest) != 1 {
		return nil, errors.New("malformed signed data")
	}
	signers, err := elements(rest[0].FullBytes, asn1.TagSet)
	if err != nil || len(signers) != 1 {
		return nil, errors.New("time-stamp token must have exactly one signer")
	}

	si, err := elements(signers[0].FullBytes, asn1.TagSequence)
	if err != nil || len(si) < 5 {
		return nil, errors.New("malformed signer info")
	}
	sd.sid = si[1]
	var digestAlg pkix.AlgorithmIdentifier
	if err := unmarshalAll(si[2].FullBytes, &digestAlg); err != nil {
		return nil, errors.New("malformed digest algorithm")
	}
	var ok bool
	if sd.digest, ok = hashAlgorithms[digestAlg.Algorithm.String()]; !ok {
		return nil, fmt.Errorf("unsupported digest algorithm %v", digestAlg.Algorithm)
	}
	if !isContext(si[3], 0) {
		return nil, errors.New("signer info has no signed attributes")
	}
	sd.signedAttrs = si[3]
	var sigAlg pkix.AlgorithmIdentifier
	if err := unmarshalAll(si[4].FullBytes, &sigAlg); err != nil {
		return nil, errors.New("malformed signature algorithm")
	}
	sd.sigAlg = sigAlg.Algorithm
	if len(si) < 6 || unmarshalAll(si[5].FullBytes, &sd.signature) != nil {
		return nil, errors.New("malformed signature")
	}
	return sd, nil
}

// signatureAlgorithm maps the signer's algorithms to an x509 algorithm,
// requiring the hash named by the signature algorithm, if any, to be the
// digest algorithm.
func (sd *signedData) signatureAlgorithm() (x509.SignatureAlgorithm, error) {
	implied := map[string]crypto.Hash{
		oidSHA256RSA.String(): crypto.SHA256, oidSHA384RSA.String(): crypto.SHA384, oidSHA512RSA.String(): crypto.SHA512,
		oidECDSASHA256.String(): crypto.SHA256, oidECDSASHA384.String(): crypto.SHA384, oidECDSASHA512.String(): crypto.SHA512,
	}
	if h, ok := implied[sd.sigAlg.String()]; ok && h != sd.digest {
		return 0, errors.New("signature and digest algorithms disagree")
	}
	switch {
	case sd.sigAlg.Equal(oidRSA), sd.sigAlg.Equal(oidSHA256RSA), sd.sigAlg.Equal(oidSHA384RSA), sd.sigAlg.Equal(oidSHA512RSA):
		return rsaAlgorithms[sd.digest], nil
	case sd.sigAlg.Equal(oidECPublicKey), sd.sigAlg.Equal(oidECDSASHA256), sd.sigAlg.Equal(oidECDSASHA384), sd.sigAlg.Equal(oidECDSASHA512):
		return ecdsaAlgorithms[sd.digest], nil
	}
	return 0, fmt.Errorf("unsupported signature algorithm %v", sd.sigAlg)
}

// verifySigner finds the signer's certificate, checks the signed
// attributes and the signature, and returns the certificate.
func (sd *signedData) verifySigner() (*x509.Certificate, error) {
	var signer *x509.Certificate
	for _, c := range sd.certs {
		if matchesSID(c, sd.sid) {
			signer = c
			break
		}
	}
	if signer == nil {
		return nil, errors.New("time-stamp token does not include the signer's certificate")
	}

	attrs, err := contents(sd.signedAttrs.Bytes)
	if err != nil {
		return nil, errors.New("malformed signed attributes")
	}
	var sawType, sawDigest, sawSigningCert bool
	for _, a := range attrs {
		parts, err := contents(a.Bytes)
		if err != nil || len(parts) != 2 || parts[1].Tag != asn1.TagSet {
			return nil, errors.New("malformed signed attribute")
		}
		var typ asn1.ObjectIdentifier
		if err := unmarshalAll(parts[0].FullBytes, &typ); err != nil {
			return nil, errors.New("malformed signed attribute")
		}
		values, err := contents(parts[1].Bytes)
		if err != nil || len(values) != 1 {
			return nil, fmt.Errorf("signed attribute %v must have one value", typ)
		}
		v := values[0].FullBytes
		switch {
		case typ.Equal(oidAttrContentType):
			var ct asn1.ObjectIdentifier
			if unmarshalAll(v, &ct) != nil || !ct.Equal(oidTSTInfo) {
				return nil, errors.New("signed content type is not TSTInfo")
			}
			sawType = true
		case typ.Equal(oidAttrMessageDigest):
			var md []byte
			h := sd.digest.New()
			h.Write(sd.eContent)
			if unmarshalAll(v, &md) != nil || !bytes.Equal(md, h.Sum(nil)) {
				return nil, errors.New("message digest does not match TSTInfo")
			}
			sawDigest = true
		case typ.Equal(oidSigningCertificate), typ.Equal(oidSigningCertificateV2):
			if err := checkSigningCertificate(v, typ.Equal(oidSigningCertificateV2), signer); err != nil {
				return nil, err
			}
			sawSigningCert = true
		}
	}
	if !sawType || !sawDigest || !sawSigningCert {
		return nil, errors.New("signed attributes must include content type, message digest and signing certificate")
	}

	algo, err := sd.signatureAlgorithm()
	if err != nil {
		return nil, err
	}
	signed := slices.Clone(sd.signedAttrs.FullBytes)
	signed[0] = 0x31 // the signature covers the attributes encoded as a SET
	if err := signer.CheckSignature(algo, signed, sd.signature); err != nil {
		return nil, fmt.Errorf("time-stamp signature: %w", err)
	}
	return signer, nil
}

func matchesSID(c *x509.Certificate, sid asn1.RawValue) bool {
	if isContext(sid, 0) { // subjectKeyIdentifier
		return len(c.SubjectKeyId) > 0 && bytes.Equal(c.SubjectKeyId, sid.Bytes)
	}
	var ias struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}
	if unmarshalAll(sid.FullBytes, &ias) != nil {
		return false
	}
	return bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.Serial) == 0
}

// checkSigningCertificate checks that the first ESS certificate ID
// identifies the signer (RFC 2634, RFC 5035).
func checkSigningCertificate(der []byte, v2 bool, signer *x509.Certificate) error {
	sc, err := elements(der, asn1.TagSequence)
	if err != nil || len(sc) == 0 {
		return errors.New("malformed signing certificate attribute")
	}
	ids, err := contents(sc[0].Bytes)
	if err != nil || len(ids) == 0 {
		return errors.New("malformed signing certificate attribute")
	}
	id, err := contents(ids[0].Bytes)
	if err != nil || len(id) == 0 {
		return errors.New("malformed ESS certificate ID")
	}
	hash := crypto.SHA1
	if v2 {
		hash = crypto.SHA256
		if id[0].Tag == asn1.TagSequence {
			var alg pkix.AlgorithmIdentifier
			if unmarshalAll(id[0].FullBytes, &alg) != nil {
				return errors.New("malformed ESS certificate ID")
			}
			var ok bool
			if hash, ok = hashAlgorithms[alg.Algorithm.String()]; !ok {
				return fmt.Errorf("unsupported ESS certificate hash %v", alg.Algorithm)
			}
			id = id[1:]
		}
	}
	var certHash []byte
	if len(id) == 0 || unmarshalAll(id[0].FullBytes, &certHash) != nil {
		return errors.New("malformed ESS certificate ID")
	}
	var sum []byte
	if hash == crypto.SHA1 {
		s := sha1.Sum(signer.Raw)
		sum = s[:]
	} else {
		h := hash.New()
		h.Write(signer.Raw)
		sum = h.Sum(nil)
	}
	if !bytes.Equal(sum, certHash) {
		return errors.New("signing certificate attribute does not identify the signer")
	}
	return nil
}

// verifyTSACert checks the TSA certificate as RFC 3161 §2.3 requires: it
// chains to a trusted root at the time of stamping and has a critical
// extended key usage of time stamping only.
func verifyTSACert(cert *x509.Certificate, pool []*x509.Certificate, roots *x509.CertPool, at time.Time) error {
	if !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}) || len(cert.UnknownExtKeyUsage) != 0 {
		return errors.New("TSA certificate is not restricted to time stamping")
	}
	critical := false
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidExtKeyUsage) {
			critical = e.Critical
		}
	}
	if !critical {
		return errors.New("TSA certificate's extended key usage is not critical")
	}
	inter := x509.NewCertPool()
	for _, c := range pool {
		inter.AddCert(c)
	}
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	})
	if err != nil {
		return fmt.Errorf("TSA certificate: %w", err)
	}
	return nil
}

type tstInfo struct {
	policy  asn1.ObjectIdentifier
	imprint messageImprint
	serial  *big.Int
	genTime time.Time
	nonce   *big.Int
}

func parseTSTInfo(der []byte) (*tstInfo, error) {
	els, err := elements(der, asn1.TagSequence)
	if err != nil || len(els) < 5 {
		return nil, errors.New("malformed TSTInfo")
	}
	var version int
	info := &tstInfo{}
	if unmarshalAll(els[0].FullBytes, &version) != nil || version != 1 {
		return nil, errors.New("unsupported TSTInfo version")
	}
	if unmarshalAll(els[1].FullBytes, &info.policy) != nil ||
		unmarshalAll(els[2].FullBytes, &info.imprint) != nil ||
		unmarshalAll(els[3].FullBytes, &info.serial) != nil ||
		els[4].Tag != asn1.TagGeneralizedTime ||
		unmarshalAll(els[4].FullBytes, &info.genTime) != nil {
		return nil, errors.New("malformed TSTInfo")
	}
	for _, e := range els[5:] {
		if e.Class == asn1.ClassUniversal && e.Tag == asn1.TagInteger {
			if unmarshalAll(e.FullBytes, &info.nonce) != nil {
				return nil, errors.New("malformed TSTInfo nonce")
			}
		}
	}
	return info, nil
}
