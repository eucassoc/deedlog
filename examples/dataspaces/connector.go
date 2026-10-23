package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/deedlog/deedlog/core"
	"github.com/deedlog/deedlog/examples/internal/demo"
)

// Message is a Dataspace Protocol message between connectors, reduced to
// what the sample needs, with the sender's latest signed checkpoint
// attached. In a real connector, such as an EDC extension, the checkpoint
// travels in a message property or HTTP header.
type Message struct {
	Type       string `json:"@type"` // dspace:ContractRequestMessage, ...
	Process    string `json:"process"`
	Agreement  string `json:"agreement,omitempty"`
	State      string `json:"state"`
	Policy     string `json:"policy,omitempty"`
	Checkpoint string `json:"-"`
}

// Connector is a dataspace participant's connector with its own chain. It
// records every protocol message it sends or receives, and the
// counterpart's checkpoint that came with it. Holding each other's
// checkpoints, two connectors witness each other's chains without a central
// log.
type Connector struct {
	Name string
	Log  *demo.Log
	// Held are the counterparts' checkpoints this connector has recorded.
	Held map[string][]byte
}

// NewConnector creates a connector with a fresh chain.
func NewConnector(name string, clock *demo.Clock) (*Connector, error) {
	l, err := demo.NewLog(name+"/dsp", clock)
	if err != nil {
		return nil, err
	}
	return &Connector{Name: name, Log: l, Held: make(map[string][]byte)}, nil
}

func (c *Connector) record(m Message, direction, peer string) error {
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	meta := map[string]string{"event": "message", "direction": direction, "peer": peer, "type": m.Type,
		"process": m.Process, "state": m.State}
	if m.Agreement != "" {
		meta["agreement"] = m.Agreement
	}
	_, err = c.Log.Append(demo.Event{Source: core.Source{Type: "connector", ID: c.Name, Collector: "examples/dataspaces"},
		MediaType: "application/json", Body: body, Meta: meta})
	return err
}

// Send records a message, signs a checkpoint covering it, and delivers
// both to the counterpart.
func (c *Connector) Send(to *Connector, m Message) error {
	if err := c.record(m, "sent", to.Name); err != nil {
		return err
	}
	note, err := c.Log.Checkpoint(context.Background())
	if err != nil {
		return err
	}
	m.Checkpoint = string(note)
	return to.Receive(c, m)
}

// Receive records a message and the sender's checkpoint, after checking the
// checkpoint with the sender's key. In a dataspace, the key comes from the
// participant's identity in the trust framework.
func (c *Connector) Receive(from *Connector, m Message) error {
	cp, err := core.VerifyCheckpoint([]byte(m.Checkpoint), from.Log.OperatorKey(), nil, 0)
	if err != nil {
		return fmt.Errorf("%s: checkpoint from %s: %w", c.Name, from.Name, err)
	}
	if err := c.record(m, "received", from.Name); err != nil {
		return err
	}
	if _, err := c.Log.Append(demo.Event{
		Source:    core.Source{Type: "connector", ID: c.Name, Collector: "examples/dataspaces"},
		MediaType: "text/plain; charset=utf-8", Body: []byte(m.Checkpoint),
		Meta: map[string]string{"event": "counterpart_checkpoint", "peer": from.Name, "origin": cp.Origin,
			"size": strconv.FormatUint(cp.Size, 10)},
	}); err != nil {
		return err
	}
	c.Held[cp.Origin] = []byte(m.Checkpoint)
	return nil
}
