package core

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ReceiptHeader is the first line of a receipt (spec/checkpoint.md §7).
const ReceiptHeader = "deedlog-receipt/v1"

// Receipt is an operator's promise that the record with LeafHash will be at
// Index of the chain Origin.
type Receipt struct {
	Origin   string
	Index    uint64
	LeafHash Hash
}

// Text returns the receipt's note text.
func (r Receipt) Text() []byte {
	return fmt.Appendf(nil, "%s\n%s\n%d\n%s\n", ReceiptHeader, r.Origin, r.Index, encodeHash(r.LeafHash))
}

// ParseReceipt parses receipt note text.
func ParseReceipt(text []byte) (Receipt, error) {
	lines := strings.SplitAfter(string(text), "\n")
	if len(lines) != 5 || lines[4] != "" || lines[0] != ReceiptHeader+"\n" {
		return Receipt{}, errors.New("not a receipt")
	}
	origin := strings.TrimSuffix(lines[1], "\n")
	if !ValidKeyName(origin) {
		return Receipt{}, fmt.Errorf("invalid origin %q", origin)
	}
	indexStr := strings.TrimSuffix(lines[2], "\n")
	index, err := strconv.ParseUint(indexStr, 10, 64)
	if err != nil || strconv.FormatUint(index, 10) != indexStr {
		return Receipt{}, fmt.Errorf("invalid index %q", indexStr)
	}
	leaf, err := decodeHash(strings.TrimSuffix(lines[3], "\n"))
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{Origin: origin, Index: index, LeafHash: leaf}, nil
}

// checkReceiptKey enforces that receipt keys are distinct from checkpoint
// keys, whose key name is the origin.
func checkReceiptKey(name, origin string) error {
	if name == origin {
		return fmt.Errorf("receipt key name must differ from the origin %q, which names the checkpoint key", origin)
	}
	return nil
}

// IssueReceipt signs a receipt with the operator's receipt key.
func IssueReceipt(r Receipt, key *Signer) ([]byte, error) {
	if err := checkReceiptKey(key.Name(), r.Origin); err != nil {
		return nil, err
	}
	if !ValidKeyName(r.Origin) {
		return nil, fmt.Errorf("invalid origin %q", r.Origin)
	}
	return key.Sign(r.Text())
}

// VerifyReceipt opens a signed receipt with the operator's receipt key.
func VerifyReceipt(note []byte, key *Verifier) (Receipt, error) {
	if key.Type() != SigEd25519 {
		return Receipt{}, errors.New("receipt key must be an Ed25519 note key")
	}
	text, _, err := openNote(note, []*Verifier{key})
	if err != nil {
		return Receipt{}, err
	}
	r, err := ParseReceipt(text)
	if err != nil {
		return Receipt{}, err
	}
	if err := checkReceiptKey(key.Name(), r.Origin); err != nil {
		return Receipt{}, err
	}
	return r, nil
}

// ReceiptStatus is the outcome of checking a receipt against a checkpoint.
type ReceiptStatus int

const (
	// ReceiptIncluded: the checkpoint includes the promised record.
	ReceiptIncluded ReceiptStatus = iota
	// ReceiptNotYetCovered: the checkpoint's tree is not yet large enough.
	ReceiptNotYetCovered
	// ReceiptBroken: the checkpoint has a different record at the index.
	ReceiptBroken
)

func (s ReceiptStatus) String() string {
	switch s {
	case ReceiptIncluded:
		return "included"
	case ReceiptNotYetCovered:
		return "not yet covered"
	case ReceiptBroken:
		return "broken"
	}
	return "unknown"
}

// CheckReceipt checks a verified receipt against a verified checkpoint,
// given the leaf hash at the receipt's index and its inclusion proof, as
// provided by the operator or anyone holding the chain (spec/checkpoint.md
// §7). If the promise is broken, it returns a proof of misbehavior built
// from the signed receipt and checkpoint. A proof that does not verify is an
// error, not evidence of misbehavior.
func CheckReceipt(receiptNote []byte, r Receipt, checkpointNote []byte, c Checkpoint, leaf Hash, proof []Hash) (ReceiptStatus, *MisbehaviorProof, error) {
	if r.Origin != c.Origin {
		return 0, nil, fmt.Errorf("receipt is for %q, checkpoint for %q", r.Origin, c.Origin)
	}
	if r.Index >= c.Size {
		return ReceiptNotYetCovered, nil, nil
	}
	if err := VerifyInclusion(r.Index, c.Size, leaf, proof, c.Root); err != nil {
		return 0, nil, fmt.Errorf("inclusion proof: %w", err)
	}
	if leaf == r.LeafHash {
		return ReceiptIncluded, nil, nil
	}
	index := r.Index
	return ReceiptBroken, &MisbehaviorProof{
		Type:        MisbehaviorType,
		Checkpoints: []string{string(checkpointNote)},
		Receipt:     string(receiptNote),
		Index:       &index,
		LeafHashes:  []string{encodeHash(leaf)},
		Proofs:      [][]string{encodeHashes(proof)},
	}, nil
}

// ReceiptURL returns the URL envelope of a signed receipt
// (spec/checkpoint.md §7.1): page, with the receipt in the fragment.
func ReceiptURL(page string, note []byte) string {
	page, _, _ = strings.Cut(page, "#")
	return page + "#r=" + base64.RawURLEncoding.EncodeToString(note)
}

// ReceiptFromURL extracts the signed receipt from a URL envelope, or from
// its fragment alone.
func ReceiptFromURL(url string) ([]byte, error) {
	_, frag, _ := strings.Cut(url, "#")
	if frag == "" {
		frag = url
	}
	for _, part := range strings.Split(frag, "&") {
		if v, ok := strings.CutPrefix(part, "r="); ok {
			note, err := base64.RawURLEncoding.DecodeString(v)
			if err != nil {
				return nil, errors.New("malformed receipt in URL")
			}
			return note, nil
		}
	}
	return nil, errors.New("URL carries no receipt")
}
