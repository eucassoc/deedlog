package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/deedlog/deedlog/core"
	"github.com/deedlog/deedlog/examples/internal/demo"
)

// The program, the voucher and the presentation, reduced to the fields the
// sample uses. In production the voucher is a verifiable credential (an
// SD-JWT VC or a W3C VC) bound to the holder's key, the presentation is a
// verifiable presentation over it, and the program is the trust list of
// issuers that verifiers use.

// Program is what the operator of a shared voucher program publishes: the
// stores that take part, with the keys they sign vouchers with, the value of
// one voucher and how long it is valid. Every store records it as the first
// entry of its chain.
type Program struct {
	Name      string   `json:"name"`
	Value     int      `json:"value"`
	ValidDays int      `json:"valid_days"`
	Stores    []Member `json:"stores"`
}

// Member is a participating store and its voucher key.
type Member struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

func (p Program) key(store string) (ed25519.PublicKey, bool) {
	for _, m := range p.Stores {
		if m.ID == store {
			k, err := base64.StdEncoding.DecodeString(m.Key)
			if err != nil || len(k) != ed25519.PublicKeySize {
				return nil, false
			}
			return k, true
		}
	}
	return nil, false
}

// Voucher is the credential: a reward of fixed value, issued by a store to
// a holder's key. It carries no name, account or contact; the store keeps
// nothing about the holder after issuing it.
type Voucher struct {
	ID       string    `json:"id"`
	Program  string    `json:"program"`
	Issuer   string    `json:"issuer"`
	Holder   string    `json:"holder"`
	Value    int       `json:"value"`
	IssuedAt time.Time `json:"issued_at"`
	Expires  time.Time `json:"expires"`
}

// Signed is a body with an Ed25519 signature over its exact bytes. The body
// is kept as signed, so that digests and signatures are checked on the same
// bytes everywhere.
type Signed struct {
	Body      json.RawMessage `json:"body"`
	Signature string          `json:"signature"`
}

func sign(key ed25519.PrivateKey, body []byte) ([]byte, error) {
	return json.Marshal(Signed{Body: body, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, body))})
}

// open checks a signed body against a public key and returns the body.
func open(pub ed25519.PublicKey, raw []byte) ([]byte, error) {
	var s Signed
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || !ed25519.Verify(pub, s.Body, sig) {
		return nil, errors.New("invalid signature")
	}
	return s.Body, nil
}

// presentation is what the holder signs when redeeming: the signed voucher
// as issued, the store it is presented to and the store's challenge, so
// that a copied voucher is worthless without the holder's key.
type presentation struct {
	Voucher   json.RawMessage `json:"voucher"`
	Store     string          `json:"store"`
	Challenge string          `json:"challenge"`
}

func source(id string) core.Source {
	return core.Source{Type: "reward-voucher", ID: id, Collector: "examples/reward-vouchers"}
}

// Store is the integration point on the store side: the point-of-sale
// system calls Issue after a purchase and Redeem when a voucher is
// presented. Both record to the store's own chain. The store holds no
// customer data; the only state it keeps is the vouchers it took itself.
type Store struct {
	ID  string
	Log *demo.Log
	// SkipExpiry makes the store accept expired vouchers, as a store with
	// a wrong clock or a lenient cashier would.
	SkipExpiry bool

	key     ed25519.PrivateKey
	program Program

	mu         sync.Mutex
	challenges map[string]bool
	taken      map[string]bool
}

// NewStore creates a store with a fresh voucher key and chain.
func NewStore(id string, clock *demo.Clock) (*Store, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	l, err := demo.NewLog(id+"/vouchers", clock)
	if err != nil {
		return nil, err
	}
	return &Store{ID: id, Log: l, key: key, challenges: make(map[string]bool), taken: make(map[string]bool)}, nil
}

// Member returns the store's entry in the program.
func (s *Store) Member() Member {
	return Member{ID: s.ID, Key: base64.StdEncoding.EncodeToString(s.key.Public().(ed25519.PublicKey))}
}

// Join records the published program as the first entry of the chain.
func (s *Store) Join(p Program, published []byte) error {
	s.program = p
	_, err := s.Log.Append(demo.Event{Source: source(s.ID), MediaType: "application/json", Body: published,
		Meta: map[string]string{"event": "program"}})
	return err
}

// Issue issues a voucher to a holder's key after a purchase and records
// it. The voucher goes to the holder; only its digest enters the chain.
func (s *Store) Issue(holder ed25519.PublicKey) ([]byte, error) { return s.issue(holder, true) }

func (s *Store) issue(holder ed25519.PublicKey, record bool) ([]byte, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	now := s.Log.Clock.Now()
	body, err := json.Marshal(Voucher{
		ID: hex.EncodeToString(id), Program: s.program.Name, Issuer: s.ID,
		Holder: base64.StdEncoding.EncodeToString(holder), Value: s.program.Value,
		IssuedAt: now, Expires: now.Add(time.Duration(s.program.ValidDays) * 24 * time.Hour),
	})
	if err != nil {
		return nil, err
	}
	v, err := sign(s.key, body)
	if err != nil {
		return nil, err
	}
	if !record {
		return v, nil
	}
	_, err = s.Log.Append(demo.Event{Source: source(s.ID), MediaType: "application/json", Body: v,
		Meta: map[string]string{"event": "issued"}})
	return v, err
}

// Challenge returns a fresh challenge for a presentation.
func (s *Store) Challenge() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	c := hex.EncodeToString(b)
	s.mu.Lock()
	s.challenges[c] = true
	s.mu.Unlock()
	return c, nil
}

// Redeem accepts a presented voucher and records the presentation. The
// checks need nothing but the published program: the issuer's signature,
// the holder's signature, the expiry, and that this store has not taken
// the voucher before. Whether another store has is found at settlement.
// The holder gets a receipt for the record.
func (s *Store) Redeem(raw []byte) ([]byte, error) {
	var signed Signed
	if err := json.Unmarshal(raw, &signed); err != nil {
		return nil, err
	}
	var p presentation
	if err := json.Unmarshal(signed.Body, &p); err != nil {
		return nil, err
	}
	if p.Store != s.ID {
		return nil, fmt.Errorf("presented to %s, not to this store", p.Store)
	}
	s.mu.Lock()
	ok := s.challenges[p.Challenge]
	delete(s.challenges, p.Challenge)
	s.mu.Unlock()
	if !ok {
		return nil, errors.New("unknown or reused challenge")
	}
	v, err := Verify(s.program, p.Voucher)
	if err != nil {
		return nil, err
	}
	if _, err := open(holderKey(v), raw); err != nil {
		return nil, fmt.Errorf("holder: %w", err)
	}
	if now := s.Log.Clock.Now(); now.After(v.Expires) && !s.SkipExpiry {
		return nil, fmt.Errorf("expired %s ago", now.Sub(v.Expires))
	}
	digest := demo.Sum(p.Voucher)
	s.mu.Lock()
	taken := s.taken[digest]
	s.taken[digest] = true
	s.mu.Unlock()
	if taken {
		return nil, errors.New("already redeemed here")
	}
	index, err := s.Log.Append(demo.Event{Source: source(s.ID), MediaType: "application/json", Body: raw,
		Meta: map[string]string{"event": "redeemed", "voucher": digest, "issuer": v.Issuer}})
	if err != nil {
		return nil, err
	}
	return s.Log.Receipt(index)
}

// Verify checks a signed voucher against the program: the issuer must be a
// member and the signature must be the issuer's.
func Verify(p Program, raw []byte) (Voucher, error) {
	var s Signed
	if err := json.Unmarshal(raw, &s); err != nil {
		return Voucher{}, err
	}
	var v Voucher
	if err := json.Unmarshal(s.Body, &v); err != nil {
		return Voucher{}, err
	}
	key, ok := p.key(v.Issuer)
	if !ok {
		return v, fmt.Errorf("issuer %s is not in the program", v.Issuer)
	}
	if _, err := open(key, raw); err != nil {
		return v, fmt.Errorf("issuer %s: %w", v.Issuer, err)
	}
	if v.Program != p.Name || v.Value != p.Value {
		return v, errors.New("voucher does not match the program")
	}
	return v, nil
}

func holderKey(v Voucher) ed25519.PublicKey {
	k, err := base64.StdEncoding.DecodeString(v.Holder)
	if err != nil || len(k) != ed25519.PublicKeySize {
		return make([]byte, ed25519.PublicKeySize)
	}
	return k
}

// Wallet is the holder's side: the customer's agent, which holds the key
// the vouchers are bound to, keeps the vouchers and presents them. In
// production this is the agent's credential wallet.
type Wallet struct {
	key ed25519.PrivateKey

	mu       sync.Mutex
	vouchers [][]byte
	// Receipts are the stores' receipts for the redemption records, by
	// store.
	Receipts map[string][][]byte
}

// NewWallet creates a wallet with a fresh key.
func NewWallet() (*Wallet, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Wallet{key: key, Receipts: make(map[string][][]byte)}, nil
}

// Key returns the key vouchers are issued to.
func (w *Wallet) Key() ed25519.PublicKey { return w.key.Public().(ed25519.PublicKey) }

// Add keeps an issued voucher.
func (w *Wallet) Add(v []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.vouchers = append(w.vouchers, v)
}

// Take removes and returns the oldest voucher still valid at now, or nil.
// Expired vouchers are dropped, as an agent would.
func (w *Wallet) Take(now time.Time) []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	for len(w.vouchers) > 0 {
		v := w.vouchers[0]
		w.vouchers = w.vouchers[1:]
		if expires(v).After(now) {
			return v
		}
	}
	return nil
}

// expires returns a signed voucher's expiry, without checking it.
func expires(raw []byte) time.Time {
	var s Signed
	var v Voucher
	if json.Unmarshal(raw, &s) != nil || json.Unmarshal(s.Body, &v) != nil {
		return time.Time{}
	}
	return v.Expires
}

// Count returns the number of vouchers held.
func (w *Wallet) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.vouchers)
}

// RedeemAt presents a voucher to a store and keeps the store's receipt.
func (w *Wallet) RedeemAt(s *Store, v []byte) error {
	c, err := s.Challenge()
	if err != nil {
		return err
	}
	body, err := json.Marshal(presentation{Voucher: v, Store: s.ID, Challenge: c})
	if err != nil {
		return err
	}
	p, err := sign(w.key, body)
	if err != nil {
		return err
	}
	receipt, err := s.Redeem(p)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.Receipts[s.ID] = append(w.Receipts[s.ID], receipt)
	w.mu.Unlock()
	return nil
}
