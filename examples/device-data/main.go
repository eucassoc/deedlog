// Command device-data runs the device-originated data use case: meters sign
// their readings, an untrusted gateway forwards them, and anyone with the
// registry of device keys can check every recorded reading.
//
//	go run ./examples/device-data [-out DIR]
package main

import (
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

const every = 15 * time.Minute

type scenario struct {
	name  string
	drop  func(device string, seq uint64) bool
	alter func(device string, seq uint64) bool
	// Whether someone injects a reading signed with a key of their own.
	forge bool
}

type result struct {
	log        *demo.Log
	witnesses  []*demo.Witness
	checkpoint []byte
	registry   map[string]*core.Verifier
	findings   demo.Findings
}

func run(sc scenario, hours int) (*result, error) {
	l, ws, err := demo.Start("energy.example/meters", time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), "witness.grid-operator.example", "witness.verifier.example")
	if err != nil {
		return nil, err
	}
	res := &result{log: l, witnesses: ws, registry: make(map[string]*core.Verifier)}
	names := []string{"meter-17.energy.example", "meter-18.energy.example"}
	devices := make(map[string]*Device)
	for _, name := range names {
		d, key, err := NewDevice(name)
		if err != nil {
			return res, err
		}
		devices[name], res.registry[name] = d, key
	}
	impostor, _, err := NewDevice(names[0])
	if err != nil {
		return res, err
	}
	gw := &Gateway{Collector: &Collector{Log: l}, Drop: sc.drop, Alter: sc.alter}

	for i := 1; i <= hours*4; i++ {
		l.Clock.Advance(every)
		for j, name := range names {
			note, err := devices[name].Measure(fmt.Sprintf("%d.%d kWh", 3+j, i%10), l.Clock.Now())
			if err != nil {
				return res, err
			}
			if err := gw.Forward(name, devices[name].seq, note); err != nil {
				return res, err
			}
		}
		if sc.forge && i == hours*2 {
			note, err := impostor.Measure("99.9 kWh", l.Clock.Now())
			if err != nil {
				return res, err
			}
			if err := gw.Collector.Receive(note); err != nil {
				return res, err
			}
		}
		if i%16 == 0 {
			if res.checkpoint, err = l.Checkpoint(context.Background(), ws...); err != nil {
				return res, err
			}
		}
	}
	if res.checkpoint, err = l.Checkpoint(context.Background(), ws...); err != nil {
		return res, err
	}
	entries, _, err := demo.Open(l.Chain(), res.checkpoint, l.OperatorKey(), demo.Keys(ws), len(ws))
	if err != nil {
		return res, err
	}
	res.findings = Check(entries, l.Body, res.registry, every)
	return res, nil
}

func main() {
	out := flag.String("out", "", "directory for the chains, checkpoints and keys (default: a new temporary directory)")
	flag.Parse()
	dir, err := demo.OutDir(*out, "device-data")
	if err != nil {
		log.Fatal(err)
	}
	for i, sc := range []scenario{
		{name: "an honest gateway"},
		{
			name:  "a gateway that drops and alters readings, and a forged reading",
			drop:  func(d string, seq uint64) bool { return d == "meter-18.energy.example" && seq >= 40 && seq < 44 },
			alter: func(d string, seq uint64) bool { return d == "meter-17.energy.example" && seq == 60 },
			forge: true,
		},
	} {
		res, err := run(sc, 24)
		if err != nil {
			log.Fatal(err)
		}
		demo.Header(os.Stdout, sc.name, res.log, res.witnesses)
		res.findings.Print(os.Stdout)
		if err := demo.Save(os.Stdout, filepath.Join(dir, fmt.Sprint(i+1)), res.log, res.witnesses); err != nil {
			log.Fatal(err)
		}
		demo.CloseAll(res.witnesses)
	}
}
