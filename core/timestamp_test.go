package core

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testdata/tsa holds real responses from public TSAs (FreeTSA, Sectigo and
// DigiCert, requested through rfc3161.ai.moda), and one from a local test TSA
// made with OpenSSL, all over checkpoint.txt. Each verified with
// "openssl ts -verify" against the root stored next to it.

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "tsa", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(readTestdata(t, name))
	if block == nil {
		t.Fatalf("%s: no PEM block", name)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func rootPool(t *testing.T, name string) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	p.AddCert(readCert(t, name))
	return p
}

var publicTSAs = []struct{ tsr, root string }{
	{"freetsa.tsr", "freetsa-root.pem"},
	{"digicert.tsr", "digicert-root.pem"},
	{"sectigo.tsr", "sectigo-root.pem"},
}

func TestVerifyTimestampPublicTSAs(t *testing.T) {
	data := readTestdata(t, "checkpoint.txt")
	nonce, _ := new(big.Int).SetString("ECA8561BD4109BA2", 16)
	for _, tc := range publicTSAs {
		t.Run(tc.tsr, func(t *testing.T) {
			ts, err := VerifyTimestamp(readTestdata(t, tc.tsr), data, rootPool(t, tc.root))
			if err != nil {
				t.Fatal(err)
			}
			if ts.Time.Year() != 2026 || ts.Time.Month() != time.October || ts.Time.Day() != 22 {
				t.Errorf("time = %v", ts.Time)
			}
			if ts.Nonce == nil || ts.Nonce.Cmp(nonce) != 0 {
				t.Errorf("nonce = %v", ts.Nonce)
			}
		})
	}
}

func TestVerifyTimestampTokenAndResponse(t *testing.T) {
	data := readTestdata(t, "checkpoint.txt")
	roots := rootPool(t, "local-root.pem")
	for _, name := range []string{"local.tsr", "local.tst"} {
		ts, err := VerifyTimestamp(readTestdata(t, name), data, roots)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !ts.Policy.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}) {
			t.Errorf("%s: policy = %v", name, ts.Policy)
		}
	}
}

func TestVerifyTimestampRejects(t *testing.T) {
	data := readTestdata(t, "checkpoint.txt")
	tsr := readTestdata(t, "sectigo.tsr")
	roots := rootPool(t, "sectigo-root.pem")

	expectErr := func(name string, tsr, data []byte, roots *x509.CertPool, want string) {
		t.Helper()
		_, err := VerifyTimestamp(tsr, data, roots)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", name, err, want)
		}
	}
	expectErr("other data", tsr, []byte("other\n"), roots, "different data")
	expectErr("untrusted root", tsr, data, rootPool(t, "local-root.pem"), "TSA certificate")

	token, err := extractToken(tsr)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := parseSignedData(token)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(part []byte) []byte {
		i := bytes.Index(tsr, part)
		if i < 0 {
			t.Fatal("part not found")
		}
		b := bytes.Clone(tsr)
		b[i+len(part)/2] ^= 1
		return b
	}
	expectErr("tampered TSTInfo", flip(sd.eContent), data, roots, "")
	expectErr("tampered signature", flip(sd.signature), data, roots, "signature")
	expectErr("truncated", tsr[:len(tsr)-10], data, roots, "")
	expectErr("rejected status", []byte{0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02}, data, roots, "rejected")
}

func TestVerifyTSACertRequiresTimeStamping(t *testing.T) {
	err := verifyTSACert(readCert(t, "local-noeku.pem"), nil, rootPool(t, "local-root.pem"), time.Now())
	if err == nil || !strings.Contains(err.Error(), "time stamping") {
		t.Fatalf("err = %v", err)
	}
}

func TestTimestampRequest(t *testing.T) {
	data := []byte("city.example/cameras\n3\nroot\n")
	der, nonce, err := TimestampRequest(data)
	if err != nil {
		t.Fatal(err)
	}
	var req timeStampReq
	if err := unmarshalAll(der, &req); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if req.Version != 1 || !req.CertReq || req.Nonce.Cmp(nonce) != 0 ||
		!req.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) ||
		!bytes.Equal(req.MessageImprint.HashedMessage, sum[:]) {
		t.Fatalf("request = %+v", req)
	}
}
