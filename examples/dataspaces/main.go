// Command dataspaces runs the dataspaces use case: a provider and a
// consumer negotiate a contract and transfer data, each connector recording
// the protocol in its own chain and holding the other's checkpoints, so
// that neither can later rewrite its history unnoticed.
//
//	go run ./examples/dataspaces [-out DIR]
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/deedlog/deedlog/core"
	"github.com/deedlog/deedlog/examples/internal/demo"
)

type scenario struct {
	name string
	// Whether the provider terminates the negotiation, then transfers
	// anyway.
	terminate bool
}

type result struct {
	provider, consumer *Connector
	findings           [2]demo.Findings
}

func run(sc scenario) (*result, error) {
	clock := demo.NewClock(time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC))
	provider, err := NewConnector("provider.example", clock)
	if err != nil {
		return nil, err
	}
	consumer, err := NewConnector("consumer.example", clock)
	if err != nil {
		return nil, err
	}
	policy := demo.Sum([]byte(`{"odrl:permission":[{"odrl:action":"use","odrl:constraint":[{"odrl:leftOperand":"purpose","odrl:rightOperand":"logistics-planning"}]}]}`))
	final := "FINALIZED"
	if sc.terminate {
		final = "TERMINATED"
	}
	steps := []struct {
		from, to *Connector
		m        Message
	}{
		{consumer, provider, Message{Type: "dspace:ContractRequestMessage", Process: "neg-1", State: "REQUESTED"}},
		{provider, consumer, Message{Type: "dspace:ContractAgreementMessage", Process: "neg-1", Agreement: "agr-1", State: "AGREED", Policy: policy}},
		{consumer, provider, Message{Type: "dspace:ContractAgreementVerificationMessage", Process: "neg-1", Agreement: "agr-1", State: "VERIFIED"}},
		{provider, consumer, Message{Type: "dspace:ContractNegotiationEventMessage", Process: "neg-1", Agreement: "agr-1", State: final}},
		{consumer, provider, Message{Type: "dspace:TransferRequestMessage", Process: "tp-1", Agreement: "agr-1", State: "REQUESTED"}},
		{provider, consumer, Message{Type: "dspace:TransferStartMessage", Process: "tp-1", Agreement: "agr-1", State: "STARTED"}},
		{provider, consumer, Message{Type: "dspace:TransferCompletionMessage", Process: "tp-1", Agreement: "agr-1", State: "COMPLETED"}},
		// A later, unrelated exchange carries the consumer's checkpoint,
		// covering the transfer, to the provider.
		{consumer, provider, Message{Type: "dspace:CatalogRequestMessage", Process: "cat-1", State: "REQUESTED"}},
	}
	for _, s := range steps {
		if err := s.from.Send(s.to, s.m); err != nil {
			return nil, err
		}
		clock.Advance(3 * time.Minute)
	}
	res := &result{provider: provider, consumer: consumer}
	for i, c := range []*Connector{provider, consumer} {
		cp, err := latest(c)
		if err != nil {
			return nil, err
		}
		entries, _, err := demo.Open(c.Log.Chain(), cp, c.Log.OperatorKey(), nil, 0)
		if err != nil {
			return nil, err
		}
		res.findings[i] = Check(entries)
	}
	return res, nil
}

// latest signs a checkpoint of the connector's whole chain.
func latest(c *Connector) ([]byte, error) { return c.Log.Checkpoint(context.Background()) }

// deny rewrites a connector's chain without the records of a transfer, as
// a consumer disputing that it received data would.
func deny(c *Connector, process string) ([]byte, error) {
	var out bytes.Buffer
	w, err := core.NewWriter(&out, c.Log.Origin)
	if err != nil {
		return nil, err
	}
	cp, err := latest(c)
	if err != nil {
		return nil, err
	}
	entries, _, err := demo.Open(c.Log.Chain(), cp, c.Log.OperatorKey(), nil, 0)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Meta["process"] != process {
			if _, err := w.Append(e.Record); err != nil {
				return nil, err
			}
		}
	}
	return out.Bytes(), nil
}

// audit checks a chain a connector presents against the checkpoint its
// counterpart holds from it.
func audit(presented, held []byte, operator *core.Verifier) error {
	c, err := core.VerifyCheckpoint(held, operator, nil, 0)
	if err != nil {
		return err
	}
	s, leaves, err := core.VerifyLeaves(bytes.NewReader(presented))
	if err != nil {
		return err
	}
	return core.CheckCheckpoint(s, leaves, c)
}

func main() {
	out := flag.String("out", "", "directory for the chains, checkpoints and keys (default: a new temporary directory)")
	flag.Parse()
	dir, err := demo.OutDir(*out, "dataspaces")
	if err != nil {
		log.Fatal(err)
	}
	for i, sc := range []scenario{
		{name: "a contract and a transfer"},
		{name: "a transfer after the negotiation was terminated", terminate: true},
	} {
		res, err := run(sc)
		if err != nil {
			log.Fatal(err)
		}
		for j, c := range []*Connector{res.provider, res.consumer} {
			fmt.Printf("== %s, %s: %d records, holding %d counterpart checkpoint(s)\n", sc.name, c.Log.Origin, c.Log.Size(), len(c.Held))
			res.findings[j].Print(os.Stdout)
		}
		if i == 0 {
			fmt.Println("\n  The consumer later presents its chain without the transfer:")
			rewritten, err := deny(res.consumer, "tp-1")
			if err != nil {
				log.Fatal(err)
			}
			held := res.provider.Held[res.consumer.Log.Origin]
			err = audit(rewritten, held, res.consumer.Log.OperatorKey())
			fmt.Printf("  against the consumer's checkpoint held by the provider: %v\n", err)
		}
		for _, c := range []*Connector{res.provider, res.consumer} {
			if err := demo.Save(os.Stdout, filepath.Join(dir, fmt.Sprint(i+1), c.Name), c.Log, nil); err != nil {
				log.Fatal(err)
			}
		}
	}
}
