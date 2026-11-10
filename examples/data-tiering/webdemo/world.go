package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/eucassoc/deedlog/core"
	"github.com/eucassoc/deedlog/examples/data-tiering/tiering"
	"github.com/eucassoc/deedlog/examples/internal/demo"
)

const origin = "city.aobadai.example/inquiries"

var policy = tiering.Policy{
	Tiers: []tiering.TierRule{
		{Name: "form-service", MaxAgeDays: 7, Next: "archive"},
		{Name: "archive", MaxAgeDays: 30},
	},
	InventoryEveryHours: 24,
}

// witnessNames are the two independent parties that cosign the city's
// checkpoints, by key name and display name.
var witnessNames = [][2]string{
	{"witness.library.aobadai.example", "あおば台市立図書館"},
	{"witness.sample-audit.example", "サンプル監査法人"},
}

// World is the simulated city: its inquiry form on an outsourced form
// service, its internal archive, the daily tiering job, and its chain with
// two witnesses. Time is simulated so that weeks pass at the press of a
// button.
type World struct {
	mu        sync.Mutex
	log       *demo.Log
	witnesses []*demo.Witness
	tiers     map[string]*tiering.Tier
	job       *tiering.Job
	rec       *tiering.Recorder
	policy    []byte

	transferDown bool      // the job moving data off the form service is broken
	breachAt     time.Time // when the form service's breach was announced
	tampered     bool      // the city rewrote its chain
	inquiries    int
}

func NewWorld() (*World, error) {
	w := &World{}
	return w, w.reset()
}

func (w *World) reset() error {
	demo.CloseAll(w.witnesses)
	start := time.Date(2026, 3, 25, 9, 0, 0, 0, time.UTC)
	var names []string
	for _, n := range witnessNames {
		names = append(names, n[0])
	}
	l, ws, err := demo.Start(origin, start, names...)
	if err != nil {
		return err
	}
	w.log, w.witnesses = l, ws
	w.transferDown, w.breachAt, w.tampered, w.inquiries = false, time.Time{}, false, 0
	w.rec = &tiering.Recorder{Log: l}
	if err := w.rec.Declare(policy); err != nil {
		return err
	}
	w.policy, _ = json.Marshal(policy)
	w.tiers = map[string]*tiering.Tier{"form-service": tiering.NewTier("form-service"), "archive": tiering.NewTier("archive")}
	w.job = &tiering.Job{Policy: policy, Tiers: w.tiers, Recorder: w.rec, MoveAfter: 2 * 24 * time.Hour}
	// A week of other residents' inquiries before the story begins.
	for range 7 {
		if err := w.otherInquiries(); err != nil {
			return err
		}
		if err := w.nextDay(); err != nil {
			return err
		}
	}
	return nil
}

// Reset starts the story over.
func (w *World) Reset() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.reset()
}

// Close stops the witnesses.
func (w *World) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	demo.CloseAll(w.witnesses)
}

func (w *World) submit(name, email, message string) (uint64, []byte, error) {
	w.inquiries++
	body, err := json.Marshal(map[string]string{"name": name, "email": email, "message": message,
		"id": fmt.Sprintf("%d", w.inquiries)})
	if err != nil {
		return 0, nil, err
	}
	w.tiers["form-service"].Put(body, w.log.Clock.Now())
	index, err := w.rec.Received("form-service", body)
	if err != nil {
		return 0, nil, err
	}
	receipt, err := w.log.Receipt(index)
	w.log.Clock.Advance(7 * time.Minute)
	return index, receipt, err
}

// Submit receives an inquiry from the form and returns its record number
// and the receipt for it.
func (w *World) Submit(name, email, message string) (uint64, []byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.submit(name, email, message)
}

func (w *World) otherInquiries() error {
	for i := range 3 {
		if _, _, err := w.submit(fmt.Sprintf("市民 %d", w.inquiries+1), "resident@example.com", []string{
			"ごみの収集日について", "保育園の空き状況について", "道路の補修について"}[i]); err != nil {
			return err
		}
	}
	return nil
}

// nextDay runs the evening's tiering job and checkpoint, and moves the
// clock to 9:00 the next day.
func (w *World) nextDay() error {
	now := w.log.Clock.Now()
	evening := time.Date(now.Year(), now.Month(), now.Day(), 23, 0, 0, 0, time.UTC)
	w.log.Clock.Advance(evening.Sub(now))
	if err := w.job.Run(map[string]bool{"form-service": w.transferDown}); err != nil {
		return err
	}
	if err := w.job.TakeInventory(); err != nil {
		return err
	}
	if err := w.checkpoint(); err != nil {
		return err
	}
	w.log.Clock.Advance(10 * time.Hour)
	return nil
}

// checkpoint has the witnesses cosign the chain. After the city rewrote its
// chain, they refuse, and the city can only publish a checkpoint signed by
// itself.
func (w *World) checkpoint() error {
	if !w.tampered {
		_, err := w.log.Checkpoint(context.Background(), w.witnesses...)
		return err
	}
	_, err := w.log.Checkpoint(context.Background())
	return err
}

// Advance lets days pass, with other residents' inquiries each day.
func (w *World) Advance(days int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for range days {
		if err := w.nextDay(); err != nil {
			return err
		}
		if err := w.otherInquiries(); err != nil {
			return err
		}
	}
	return nil
}

// SetTransferDown breaks or repairs the job moving data off the form
// service.
func (w *World) SetTransferDown(down bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.transferDown = down
}

// Breach announces that the form service was breached.
func (w *World) Breach() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.breachAt.IsZero() {
		w.breachAt = w.log.Clock.Now()
	}
}

// Tamper has the city rewrite its chain without the records that show
// inquiries kept on the form service too long, and publish the result.
func (w *World) Tamper() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	entries, err := w.entries()
	if err != nil {
		return err
	}
	late := make(map[string]bool)
	for _, f := range tiering.Check(entries, w.policy) {
		if f.Line > 0 {
			late[entries[f.Line-1].Subject.Digest["hmac-sha256"]] = true
		}
	}
	if err := w.log.Rewrite(func(r core.Record) bool {
		h := r.Subject.Digest["hmac-sha256"]
		return h == "" || !late[h]
	}); err != nil {
		return err
	}
	w.tampered = true
	return w.checkpoint()
}

func (w *World) entries() ([]demo.Entry, error) {
	entries, _, err := demo.Open(w.log.Chain(), w.log.Latest(), w.log.OperatorKey(), nil, 0)
	return entries, err
}

// State is what the demo panel shows.
type State struct {
	Now          time.Time
	TransferDown bool
	BreachAt     time.Time
	Tampered     bool
}

func (w *World) State() State {
	w.mu.Lock()
	defer w.mu.Unlock()
	return State{Now: w.log.Clock.Now(), TransferDown: w.transferDown, BreachAt: w.breachAt, Tampered: w.tampered}
}

// Published is what the city publishes for anyone to check: its latest
// checkpoint, its chain (records hold only keyed digests) and its policy.
func (w *World) Published() (checkpoint, chain, policy []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.log.Latest(), w.log.Chain(), w.policy
}

// Keys returns the public keys a verifier needs.
func (w *World) Keys() (operator, receipts *core.Verifier, witnesses []*core.Verifier) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.log.OperatorKey(), w.log.ReceiptKey(), demo.Keys(w.witnesses)
}
