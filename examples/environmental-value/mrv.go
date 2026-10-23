package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/deedlog/deedlog/core"
	"github.com/deedlog/deedlog/examples/internal/demo"
)

// Two chains take part: the metering chain, where readings are recorded as
// they arrive (see the device-data sample for readings signed by the
// meter), and the project's MRV chain, where reports, verification,
// issuance and claims are recorded.

// Reading is the evidence body of one meter reading.
type Reading struct {
	Meter string  `json:"meter"`
	Seq   int     `json:"seq"`
	KWh   float64 `json:"kwh"`
}

// Ref points to a record in another chain by its index and leaf hash, so
// that the reference cannot be redirected to a different record.
// References between chains are planned in the specification; this is the
// sample's own convention until then.
type Ref struct {
	Chain string `json:"chain"`
	Index uint64 `json:"index"`
	Leaf  string `json:"leaf"`
}

// Report aggregates readings for a period.
type Report struct {
	Period   string  `json:"period"`
	TotalKWh float64 `json:"total_kwh"`
	Inputs   []Ref   `json:"inputs"`
}

// Statement is a third-party verifier's statement about a report.
type Statement struct {
	Report      string  `json:"report"` // sha256 of the report body
	VerifiedKWh float64 `json:"verified_kwh"`
}

// Certificate is the registry's confirmation of issuance.
type Certificate struct {
	ID        string `json:"id"`
	Statement string `json:"statement"` // sha256 of the statement body
	MWh       int    `json:"mwh"`
}

// Claim is an end user's claim of a certificate, for example in its
// annual report.
type Claim struct {
	Certificate string `json:"certificate"`
	Claimant    string `json:"claimant"`
	Year        int    `json:"year"`
}

func source(typ, id string) core.Source {
	return core.Source{Type: typ, ID: id, Collector: "examples/environmental-value"}
}

// Metering records readings as the metering system receives them.
type Metering struct {
	Log *demo.Log
}

// Record appends a reading and returns a reference to it.
func (m *Metering) Record(r Reading) (Ref, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return Ref{}, err
	}
	index, err := m.Log.Append(demo.Event{Source: source("meter", r.Meter), MediaType: "application/json", Body: body,
		Meta: map[string]string{"event": "reading", "meter": r.Meter, "seq": strconv.Itoa(r.Seq)}})
	if err != nil {
		return Ref{}, err
	}
	leaf, _, err := m.Log.Proof(index, index+1)
	if err != nil {
		return Ref{}, err
	}
	return Ref{Chain: m.Log.Origin, Index: index, Leaf: base64.StdEncoding.EncodeToString(leaf[:])}, nil
}

// MRV records each stage of measurement, reporting and verification, and
// the certificate's life in the registry. Each body is the document itself:
// the report, the verifier's statement, the registry's confirmation.
type MRV struct {
	Log *demo.Log
}

func (m *MRV) record(src core.Source, event string, v any, meta map[string]string) ([]byte, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	meta["event"] = event
	_, err = m.Log.Append(demo.Event{Source: src, MediaType: "application/json", Body: body, Meta: meta})
	return body, err
}

// Report records an aggregated report.
func (m *MRV) Report(r Report) ([]byte, error) {
	return m.record(source("operator", "aggregation"), "report", r, map[string]string{"period": r.Period})
}

// Verified records a verifier's statement.
func (m *MRV) Verified(s Statement, verifier string) ([]byte, error) {
	return m.record(source("verifier", verifier), "verified", s, map[string]string{})
}

// Issued records the registry's confirmation of issuance.
func (m *MRV) Issued(c Certificate, registry string) ([]byte, error) {
	return m.record(source("registry", registry), "issued", c, map[string]string{"certificate": c.ID})
}

// Claimed records a claim of a certificate.
func (m *MRV) Claimed(c Claim) ([]byte, error) {
	return m.record(source("claimant", c.Claimant), "claimed", c, map[string]string{"certificate": c.Certificate})
}

func (r Reading) String() string { return fmt.Sprintf("%s #%d", r.Meter, r.Seq) }
