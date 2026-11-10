package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/eucassoc/deedlog/core"
	"github.com/eucassoc/deedlog/examples/internal/demo"
)

// The platform hosts several municipalities (tenants). Residents give
// consent per service and purpose; services request residents' data
// through the platform's data API.

func source(component string) core.Source {
	return core.Source{Type: "data-platform", ID: component, Collector: "examples/municipal-data-platform"}
}

// Recorder is the integration point, called by consent management and by
// the data API. Residents appear only as keyed pseudonyms (HMAC of the
// resident ID), so that an auditor can link a resident's consent to the
// provisions of their data without learning who they are.
type Recorder struct {
	Log *demo.Log
}

func (r *Recorder) pseudonym(resident string) string { return r.Log.HMAC([]byte(resident)) }

// Consent records consent given or withdrawn, and returns its index so
// that the resident can be given a receipt.
func (r *Recorder) Consent(c Consent, action string) (uint64, error) {
	body, err := json.Marshal(c)
	if err != nil {
		return 0, err
	}
	return r.Log.Append(demo.Event{Source: source("consent"), MediaType: "application/json", Body: body, Keyed: true,
		Meta: map[string]string{"event": "consent", "action": action, "resident": r.pseudonym(c.Resident),
			"tenant": c.Tenant, "service": c.Service, "purpose": c.Purpose}})
}

// Access records an access decision of the data API, and for allowed
// requests the provision of data, by keyed digest of the response.
func (r *Recorder) Access(req Request, allowed bool, response []byte) error {
	meta := map[string]string{"event": "denied", "resident": r.pseudonym(req.Resident), "tenant": req.Tenant,
		"service": req.Service, "service_tenant": req.ServiceTenant, "purpose": req.Purpose}
	if allowed {
		meta["event"] = "provided"
	}
	body := response
	if !allowed {
		var err error
		if body, err = json.Marshal(req); err != nil {
			return err
		}
	}
	_, err := r.Log.Append(demo.Event{Source: source("data-api"), MediaType: "application/json", Body: body, Keyed: true, Meta: meta})
	return err
}

// Consent is a resident's consent for one service and purpose.
type Consent struct {
	Resident string `json:"resident"`
	Tenant   string `json:"tenant"`
	Service  string `json:"service"`
	Purpose  string `json:"purpose"`
}

// Request is a service's request for a resident's data.
type Request struct {
	Service       string `json:"service"`
	ServiceTenant string `json:"service_tenant"`
	Resident      string `json:"resident"`
	Tenant        string `json:"tenant"`
	Purpose       string `json:"purpose"`
}

// Platform is a stand-in for the data platform: consent management and a
// data API. The Bugs fields simulate faults found in real deployments.
type Platform struct {
	Recorder *Recorder
	Bugs     struct {
		// IgnoreWithdrawal makes the API keep using withdrawn consent.
		IgnoreWithdrawal bool
		// LooseScope checks consent by resident and purpose only, ignoring
		// which service, and which tenant, is asking.
		LooseScope bool
	}

	mu      sync.Mutex
	consent map[Consent]bool
	cached  map[Consent]bool
}

// Give records consent and returns a receipt for it.
func (p *Platform) Give(c Consent) ([]byte, error) { return p.set(c, true) }

// Withdraw records the withdrawal of consent and returns a receipt for it.
func (p *Platform) Withdraw(c Consent) ([]byte, error) { return p.set(c, false) }

func (p *Platform) set(c Consent, given bool) ([]byte, error) {
	p.mu.Lock()
	if p.consent == nil {
		p.consent, p.cached = make(map[Consent]bool), make(map[Consent]bool)
	}
	p.consent[c] = given
	if given || !p.Bugs.IgnoreWithdrawal {
		p.cached[c] = given
	}
	p.mu.Unlock()
	action := map[bool]string{true: "given", false: "withdrawn"}[given]
	index, err := p.Recorder.Consent(c, action)
	if err != nil {
		return nil, err
	}
	return p.Recorder.Log.Receipt(index)
}

// ErrDenied is returned for requests the platform refuses.
var ErrDenied = errors.New("access denied")

// Get serves a request for a resident's data.
func (p *Platform) Get(req Request) ([]byte, error) {
	p.mu.Lock()
	sameTenant := req.ServiceTenant == req.Tenant
	consented := p.cached[Consent{Resident: req.Resident, Tenant: req.Tenant, Service: req.Service, Purpose: req.Purpose}]
	if p.Bugs.LooseScope {
		sameTenant = true
		for c, given := range p.cached {
			consented = consented || (given && c.Resident == req.Resident && c.Purpose == req.Purpose)
		}
	}
	p.mu.Unlock()
	if !sameTenant || !consented {
		return nil, errors.Join(ErrDenied, p.Recorder.Access(req, false, nil))
	}
	data := fmt.Appendf(nil, `{"resident":%q,"household":3,"needs_support":true}`, req.Resident)
	if err := p.Recorder.Access(req, true, data); err != nil {
		return nil, err
	}
	return data, nil
}

// Handler exposes the data API over HTTP, as services call it.
func (p *Platform) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		data, err := p.Get(req)
		if errors.Is(err, ErrDenied) {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		if err != nil {
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})
}
