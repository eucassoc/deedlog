package main

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/deedlog/deedlog/core"
	"github.com/deedlog/deedlog/examples/internal/demo"
)

// readingHeader is the first line of the sample's reading format. Source
// signatures in records are planned in the specification; until then a
// device signs its readings as signed notes, which are the evidence bodies.
const readingHeader = "sample-device-reading/v1"

// Reading is the text a device signs.
type Reading struct {
	Device string
	Seq    uint64
	Time   time.Time
	Value  string
}

func (r Reading) text() []byte {
	return fmt.Appendf(nil, "%s\n%s\n%d\n%s\n%s\n", readingHeader, r.Device, r.Seq, r.Time.UTC().Format(time.RFC3339), r.Value)
}

func parseReading(text []byte) (Reading, error) {
	lines := strings.Split(strings.TrimSuffix(string(text), "\n"), "\n")
	if len(lines) != 5 || lines[0] != readingHeader {
		return Reading{}, errors.New("not a reading")
	}
	seq, err := strconv.ParseUint(lines[2], 10, 64)
	if err != nil {
		return Reading{}, fmt.Errorf("sequence number: %w", err)
	}
	t, err := time.Parse(time.RFC3339, lines[3])
	if err != nil {
		return Reading{}, fmt.Errorf("time: %w", err)
	}
	return Reading{Device: lines[1], Seq: seq, Time: t, Value: lines[4]}, nil
}

// Device holds its own key and numbers its readings, so that each reading
// can be attributed to it and gaps become visible.
type Device struct {
	key *core.Signer
	seq uint64
}

// NewDevice creates a device and returns its public key for the registry.
func NewDevice(name string) (*Device, *core.Verifier, error) {
	skey, _, err := core.GenerateKey(name)
	if err != nil {
		return nil, nil, err
	}
	s, err := core.NewSigner(skey)
	if err != nil {
		return nil, nil, err
	}
	return &Device{key: s}, s.Verifier(), nil
}

// Measure signs the next reading.
func (d *Device) Measure(value string, t time.Time) ([]byte, error) {
	d.seq++
	return d.key.Sign(Reading{Device: d.key.Name(), Seq: d.seq, Time: t, Value: value}.text())
}

// Collector records every reading it receives, exactly as received. It
// does not need to trust the gateway that delivered it: the device's
// signature is checked against the record later, by anyone.
type Collector struct {
	Log *demo.Log
}

// Receive records a signed reading.
func (c *Collector) Receive(note []byte) error {
	meta := map[string]string{"event": "reading"}
	// The device and sequence number are copied into meta for lookups.
	// They are claims until the signature has been checked.
	if i := bytes.LastIndex(note, []byte("\n\n")); i >= 0 {
		if r, err := parseReading(note[:i+1]); err == nil {
			meta["device"], meta["seq"] = r.Device, strconv.FormatUint(r.Seq, 10)
		}
	}
	_, err := c.Log.Append(demo.Event{
		Source:    core.Source{Type: "device", ID: meta["device"], Collector: "examples/device-data"},
		MediaType: "text/plain; charset=utf-8",
		Body:      note,
		Meta:      meta,
	})
	return err
}

// Gateway forwards readings from devices to the collector. It is not
// trusted; Drop and Alter simulate a faulty or dishonest one.
type Gateway struct {
	Collector *Collector
	Drop      func(device string, seq uint64) bool
	Alter     func(device string, seq uint64) bool
}

// Forward passes a reading on, unless the gateway drops or alters it.
func (g *Gateway) Forward(device string, seq uint64, note []byte) error {
	if g.Drop != nil && g.Drop(device, seq) {
		return nil
	}
	if g.Alter != nil && g.Alter(device, seq) {
		note = bytes.Replace(note, []byte("kWh"), []byte("0 kWh"), 1)
	}
	return g.Collector.Receive(note)
}
