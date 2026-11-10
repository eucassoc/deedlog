// Package tiering records data tiering (submissions moving between tiers
// and being deleted on schedule) and checks a chain against the declared
// policy. It is shared by the data tiering sample and its web demo.
package tiering

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/eucassoc/deedlog/core"
	"github.com/eucassoc/deedlog/examples/internal/demo"
)

// Policy is the operator's declared tiering policy. It is published and
// recorded as the first entry of the chain.
type Policy struct {
	Tiers []TierRule `json:"tiers"`
	// InventoryEveryHours is how often every tier reports what it holds.
	InventoryEveryHours int `json:"inventory_every_hours"`
}

// TierRule says how long data may stay in a tier, and where it goes next
// ("" means it is deleted).
type TierRule struct {
	Name       string `json:"name"`
	MaxAgeDays int    `json:"max_age_days"`
	Next       string `json:"next,omitempty"`
}

func (p Policy) rule(name string) (TierRule, bool) {
	for _, t := range p.Tiers {
		if t.Name == name {
			return t, true
		}
	}
	return TierRule{}, false
}

// Recorder is the integration point: the form webhook and the tiering
// jobs call it whenever data enters, leaves or is counted in a tier.
// Submissions are personal data, so records carry only their HMAC.
type Recorder struct {
	Log *demo.Log
}

var source = func(id string) core.Source {
	return core.Source{Type: "tiering", ID: id, Collector: "examples/data-tiering"}
}

// Declare records the policy. It must be the first record.
func (r *Recorder) Declare(p Policy) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = r.Log.Append(demo.Event{Source: source("operator"), MediaType: "application/json", Body: body,
		Meta: map[string]string{"event": "policy"}})
	return err
}

// Received records a submission arriving in a tier.
func (r *Recorder) Received(tier string, submission []byte) (uint64, error) {
	return r.Log.Append(demo.Event{Source: source(tier), MediaType: "application/json", Body: submission, Keyed: true,
		Meta: map[string]string{"event": "received", "tier": tier}})
}

// Moved records a submission moving between tiers.
func (r *Recorder) Moved(from, to string, submission []byte) error {
	_, err := r.Log.Append(demo.Event{Source: source(from), MediaType: "application/json", Body: submission, Keyed: true,
		Meta: map[string]string{"event": "moved", "from": from, "to": to}})
	return err
}

// Deleted records a submission deleted from a tier.
func (r *Recorder) Deleted(tier string, submission []byte) error {
	_, err := r.Log.Append(demo.Event{Source: source(tier), MediaType: "application/json", Body: submission, Keyed: true,
		Meta: map[string]string{"event": "deleted", "tier": tier}})
	return err
}

// Inventory records how many items a tier actually holds. The body lists
// their HMACs, so an auditor given the body can compare item by item. A
// count that differs from what the chain says the tier should hold reveals
// data that entered or left the tier without being recorded.
func (r *Recorder) Inventory(t *Tier) error {
	held := t.inventory(r.Log)
	body, err := json.Marshal(held)
	if err != nil {
		return err
	}
	_, err = r.Log.Append(demo.Event{Source: source(t.Name), MediaType: "application/json", Body: body,
		Meta: map[string]string{"event": "inventory", "tier": t.Name, "count": strconv.Itoa(len(held))}})
	return err
}

// Tier is a place where submissions are kept: the form service, an
// archive. In a product this is a SaaS API, a bucket or a database table.
type Tier struct {
	Name  string
	mu    sync.Mutex
	items map[string]item
}

type item struct {
	body  []byte
	since time.Time
}

func NewTier(name string) *Tier { return &Tier{Name: name, items: make(map[string]item)} }

func (t *Tier) Put(body []byte, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.items[string(body)] = item{body: body, since: now}
}

func (t *Tier) take(olderThan time.Time) [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out [][]byte
	for k, it := range t.items {
		if !it.since.After(olderThan) {
			out = append(out, it.body)
			delete(t.items, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i]) < string(out[j]) })
	return out
}

func (t *Tier) inventory(l *demo.Log) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	held := []string{}
	for _, it := range t.items {
		held = append(held, l.HMAC(it.body))
	}
	sort.Strings(held)
	return held
}

// Webhook receives submissions from the form service, records them and
// answers with a receipt link that the form shows to the person.
type Webhook struct {
	Tier     *Tier
	Recorder *Recorder
	Page     string // verification page for receipt links
}

func (h *Webhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || r.Method != http.MethodPost {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	h.Tier.Put(body, h.Recorder.Log.Clock.Now())
	index, err := h.Recorder.Received(h.Tier.Name, body)
	if err != nil {
		http.Error(w, "cannot record", http.StatusInternalServerError)
		return
	}
	receipt, err := h.Recorder.Log.Receipt(index)
	if err != nil {
		http.Error(w, "cannot issue receipt", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"receipt_url": core.ReceiptURL(h.Page, receipt)})
}

// Job is the daily tiering job: it moves submissions on from tiers that
// have a next tier, deletes them from the last one, and takes inventory.
type Job struct {
	Policy   Policy
	Tiers    map[string]*Tier
	Recorder *Recorder
	// MoveAfter is how long submissions stay on the form service so that
	// they can be answered.
	MoveAfter time.Duration
}

// Run moves and deletes what is due. Skip lets the samples simulate an
// outage of one tier's job.
func (j *Job) Run(skip map[string]bool) error {
	now := j.Recorder.Log.Clock.Now()
	for _, rule := range j.Policy.Tiers {
		if skip[rule.Name] {
			continue
		}
		t := j.Tiers[rule.Name]
		if rule.Next != "" {
			for _, b := range t.take(now.Add(-j.MoveAfter)) {
				j.Tiers[rule.Next].Put(b, now)
				if err := j.Recorder.Moved(rule.Name, rule.Next, b); err != nil {
					return err
				}
			}
			continue
		}
		// Delete a day early, since the job runs daily.
		due := now.Add(-time.Duration(rule.MaxAgeDays)*24*time.Hour + 24*time.Hour)
		for _, b := range t.take(due) {
			if err := j.Recorder.Deleted(rule.Name, b); err != nil {
				return err
			}
		}
	}
	return nil
}

// TakeInventory records an inventory of every tier.
func (j *Job) TakeInventory() error {
	for _, rule := range j.Policy.Tiers {
		if err := j.Recorder.Inventory(j.Tiers[rule.Name]); err != nil {
			return err
		}
	}
	return nil
}
