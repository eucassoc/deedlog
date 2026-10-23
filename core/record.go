// Package core implements the deedlog evidence chain: an append-only
// sequence of evidence records, each linked to the previous one by the
// digest of its exact serialized bytes.
//
// See spec/evidence-chain.md for the normative description.
package core

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// SpecVersion identifies the version of the record format.
const SpecVersion = "deedlog/v0.1"

// Record is one piece of evidence in a chain.
//
// A record does not carry the evidence itself, only its digest. The
// evidence body (a log line, a screenshot, an API response) is stored
// separately and verified against Subject.Digest.
type Record struct {
	Spec        string            `json:"spec"`
	Chain       string            `json:"chain"`
	Seq         uint64            `json:"seq"`
	Prev        string            `json:"prev,omitempty"`
	CollectedAt time.Time         `json:"collected_at"`
	Source      Source            `json:"source"`
	Subject     Subject           `json:"subject"`
	Meta        map[string]string `json:"meta,omitempty"`
}

// Source describes where and how the evidence was collected.
type Source struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Collector string `json:"collector"`
}

// Subject identifies the evidence body by digest.
type Subject struct {
	MediaType string            `json:"media_type"`
	Size      int64             `json:"size"`
	Digest    map[string]string `json:"digest"`
	URI       string            `json:"uri,omitempty"`
}

// Digest returns the "sha256:<hex>" digest of b.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// validDigest reports whether d has the form "sha256:<64 lowercase hex>".
func validDigest(d string) bool {
	h, ok := strings.CutPrefix(d, "sha256:")
	if !ok || len(h) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil && strings.ToLower(h) == h
}
