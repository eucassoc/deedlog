package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"

	"github.com/eucassoc/deedlog/core"
	"github.com/eucassoc/deedlog/examples/internal/demo"
)

// The x402 messages, reduced to the fields the sample uses. See
// https://x402.org for the protocol.

// Requirements is one way to pay, offered in a 402 response.
type Requirements struct {
	Scheme            string `json:"scheme"`
	Network           string `json:"network"`
	MaxAmountRequired string `json:"maxAmountRequired"`
	Resource          string `json:"resource"`
	PayTo             string `json:"payTo"`
	Asset             string `json:"asset"`
}

// PaymentRequired is the body of a 402 response.
type PaymentRequired struct {
	X402Version int            `json:"x402Version"`
	Error       string         `json:"error"`
	Accepts     []Requirements `json:"accepts"`
}

// Payment is the payload of the X-PAYMENT header.
type Payment struct {
	X402Version int    `json:"x402Version"`
	Scheme      string `json:"scheme"`
	Network     string `json:"network"`
	Payload     struct {
		From      string `json:"from"`
		Amount    string `json:"amount"`
		Nonce     string `json:"nonce"`
		Signature string `json:"signature"`
	} `json:"payload"`
}

// Settlement is the payload of the X-PAYMENT-RESPONSE header.
type Settlement struct {
	Success     bool   `json:"success"`
	Transaction string `json:"transaction"`
	Network     string `json:"network"`
	Payer       string `json:"payer"`
}

// Facilitator verifies and settles payments. In production this is an x402
// facilitator service that settles on a blockchain; the sample uses a
// stand-in.
type Facilitator interface {
	Settle(p Payment, req Requirements) (Settlement, error)
}

// ReceiptHeader carries the server's receipt for the delivery record.
const ReceiptHeader = "X-Deedlog-Receipt"

func source(id string) core.Source {
	return core.Source{Type: "x402", ID: id, Collector: "examples/agent-payments"}
}

// Paywall is server middleware: it asks for payment, settles it, serves the
// resource and records each step. The client gets a receipt for the record
// of what it was served.
type Paywall struct {
	Price       Requirements
	Facilitator Facilitator
	Log         *demo.Log
	Next        http.Handler
}

func (p *Paywall) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	price := p.Price
	price.Resource = r.URL.String()
	header := r.Header.Get("X-PAYMENT")
	if header == "" {
		body, _ := json.Marshal(PaymentRequired{X402Version: 1, Error: "X-PAYMENT header is required", Accepts: []Requirements{price}})
		if _, err := p.Log.Append(demo.Event{Source: source("server"), MediaType: "application/json", Body: body,
			Meta: map[string]string{"event": "payment_required", "resource": price.Resource}}); err != nil {
			http.Error(w, "cannot record", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPaymentRequired)
		w.Write(body)
		return
	}

	raw, err := base64.StdEncoding.DecodeString(header)
	var pay Payment
	if err != nil || json.Unmarshal(raw, &pay) != nil {
		http.Error(w, "malformed X-PAYMENT", http.StatusBadRequest)
		return
	}
	s, err := p.Facilitator.Settle(pay, price)
	if err != nil {
		http.Error(w, "payment rejected: "+err.Error(), http.StatusPaymentRequired)
		return
	}
	// The payment payload is recorded by digest; the transaction itself is
	// on the blockchain, so its hash goes into meta for cross-checking.
	if _, err := p.Log.Append(demo.Event{Source: source("server"), MediaType: "application/json", Body: raw,
		Meta: map[string]string{"event": "settled", "resource": price.Resource, "tx": s.Transaction, "amount": pay.Payload.Amount}}); err != nil {
		http.Error(w, "cannot record", http.StatusInternalServerError)
		return
	}

	rec := httptest.NewRecorder()
	p.Next.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		http.Error(w, "resource unavailable", http.StatusBadGateway)
		return
	}
	body := rec.Body.Bytes()
	index, err := p.Log.Append(demo.Event{Source: source("server"), MediaType: rec.Header().Get("Content-Type"), Body: body,
		Meta: map[string]string{"event": "delivered", "resource": price.Resource, "tx": s.Transaction}})
	if err != nil {
		http.Error(w, "cannot record", http.StatusInternalServerError)
		return
	}
	receipt, err := p.Log.Receipt(index)
	if err != nil {
		http.Error(w, "cannot issue receipt", http.StatusInternalServerError)
		return
	}
	settlement, _ := json.Marshal(s)
	w.Header().Set("X-PAYMENT-RESPONSE", base64.StdEncoding.EncodeToString(settlement))
	w.Header().Set(ReceiptHeader, base64.RawURLEncoding.EncodeToString(receipt))
	w.Header().Set("Content-Type", rec.Header().Get("Content-Type"))
	w.Write(body)
}

// Wallet signs payments. In production this is the agent's wallet.
type Wallet struct {
	Address string
}

func (wl Wallet) pay(req Requirements) (Payment, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return Payment{}, err
	}
	p := Payment{X402Version: 1, Scheme: req.Scheme, Network: req.Network}
	p.Payload.From = wl.Address
	p.Payload.Amount = req.MaxAmountRequired
	p.Payload.Nonce = hex.EncodeToString(nonce)
	p.Payload.Signature = "stand-in"
	return p, nil
}

// Purchase is what the agent keeps for each purchase: the response body and
// the server's receipt, which together settle any dispute about delivery.
type Purchase struct {
	Resource   string
	Settlement Settlement
	Body       []byte
	Receipt    []byte
}

// Client is the agent side: it pays when asked, records what it paid for
// and what it received in its own chain, and keeps receipts.
type Client struct {
	HTTP   *http.Client
	Wallet Wallet
	Log    *demo.Log
	// MaxAmount is the most the agent may pay for one resource.
	MaxAmount int
}

// Get fetches a resource, paying for it if required.
func (c *Client) Get(url string) (*Purchase, error) {
	resp, err := c.HTTP.Get(url)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	var pr PaymentRequired
	if err := json.Unmarshal(body, &pr); err != nil || len(pr.Accepts) == 0 {
		return nil, errors.New("malformed payment requirements")
	}
	req := pr.Accepts[0]
	if amount, err := strconv.Atoi(req.MaxAmountRequired); err != nil || amount > c.MaxAmount {
		return nil, fmt.Errorf("price %s exceeds the agent's limit", req.MaxAmountRequired)
	}
	pay, err := c.Wallet.pay(req)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(pay)
	if _, err := c.Log.Append(demo.Event{Source: source("agent"), MediaType: "application/json", Body: raw,
		Meta: map[string]string{"event": "paid", "resource": url, "amount": req.MaxAmountRequired}}); err != nil {
		return nil, err
	}

	hreq, _ := http.NewRequest(http.MethodGet, url, nil)
	hreq.Header.Set("X-PAYMENT", base64.StdEncoding.EncodeToString(raw))
	resp, err = c.HTTP.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	p := &Purchase{Resource: url, Body: body}
	if s, err := base64.StdEncoding.DecodeString(resp.Header.Get("X-PAYMENT-RESPONSE")); err == nil {
		json.Unmarshal(s, &p.Settlement)
	}
	p.Receipt, _ = base64.RawURLEncoding.DecodeString(resp.Header.Get(ReceiptHeader))
	meta := map[string]string{"event": "received", "resource": url, "status": strconv.Itoa(resp.StatusCode), "tx": p.Settlement.Transaction}
	if _, err := c.Log.Append(demo.Event{Source: source("agent"), MediaType: resp.Header.Get("Content-Type"), Body: body, Meta: meta}); err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return p, fmt.Errorf("%s: paid, but got %s", url, resp.Status)
	}
	return p, nil
}

// StandInFacilitator settles payments without a blockchain, returning a
// made-up transaction hash. Replayed nonces are rejected, as a real
// facilitator would.
type StandInFacilitator struct {
	mu   sync.Mutex
	seen map[string]bool
	n    int
	// Repeat makes the stand-in return the previous transaction hash once,
	// to simulate a faulty facilitator.
	Repeat bool
	last   string
}

func (f *StandInFacilitator) Settle(p Payment, req Requirements) (Settlement, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen == nil {
		f.seen = make(map[string]bool)
	}
	if f.seen[p.Payload.Nonce] {
		return Settlement{}, errors.New("nonce already used")
	}
	if p.Payload.Amount != req.MaxAmountRequired {
		return Settlement{}, errors.New("wrong amount")
	}
	f.seen[p.Payload.Nonce] = true
	f.n++
	tx := "0x" + demo.Sum(bytes.Repeat([]byte{byte(f.n)}, 8))[:64]
	if f.Repeat && f.last != "" {
		tx, f.Repeat = f.last, false
	}
	f.last = tx
	return Settlement{Success: true, Transaction: tx, Network: req.Network, Payer: p.Payload.From}, nil
}
