package core

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Checkpoint is the note text of a c2sp.org/tlog-checkpoint
// (spec/checkpoint.md §3).
type Checkpoint struct {
	Origin string
	Size   uint64
	Root   Hash
}

// Text returns the checkpoint's note text.
func (c Checkpoint) Text() []byte {
	return fmt.Appendf(nil, "%s\n%d\n%s\n", c.Origin, c.Size, base64.StdEncoding.EncodeToString(c.Root[:]))
}

// ParseCheckpoint parses checkpoint note text. Extension lines are rejected.
func ParseCheckpoint(text []byte) (Checkpoint, error) {
	lines := strings.SplitAfter(string(text), "\n")
	if len(lines) != 4 || lines[3] != "" {
		return Checkpoint{}, errors.New("checkpoint must have exactly three lines")
	}
	origin := strings.TrimSuffix(lines[0], "\n")
	if !ValidKeyName(origin) {
		return Checkpoint{}, fmt.Errorf("invalid origin %q", origin)
	}
	sizeStr := strings.TrimSuffix(lines[1], "\n")
	size, err := strconv.ParseUint(sizeStr, 10, 64)
	if err != nil || strconv.FormatUint(size, 10) != sizeStr {
		return Checkpoint{}, fmt.Errorf("invalid tree size %q", sizeStr)
	}
	root, err := decodeBase64(strings.TrimSuffix(lines[2], "\n"))
	if err != nil || len(root) != len(Hash{}) {
		return Checkpoint{}, errors.New("invalid root hash")
	}
	if size == 0 && Hash(root) != EmptyRoot {
		return Checkpoint{}, errors.New("empty checkpoint must have the empty root hash")
	}
	return Checkpoint{Origin: origin, Size: size, Root: Hash(root)}, nil
}

// CheckpointOf parses the checkpoint in a signed note WITHOUT verifying
// any signature. Use VerifyCheckpoint unless the signatures do not matter,
// as when serving or time-stamping one's own checkpoint.
func CheckpointOf(note []byte) (Checkpoint, error) {
	text, _, err := parseNote(note)
	if err != nil {
		return Checkpoint{}, err
	}
	return ParseCheckpoint(text)
}

// SignCheckpoint returns c signed by the operator. The signer's key name
// must be the origin.
func SignCheckpoint(c Checkpoint, operator *Signer) ([]byte, error) {
	if operator.Name() != c.Origin {
		return nil, fmt.Errorf("key name %q does not match origin %q", operator.Name(), c.Origin)
	}
	if !ValidKeyName(c.Origin) {
		return nil, fmt.Errorf("invalid origin %q", c.Origin)
	}
	return operator.Sign(c.Text())
}

// Cosign returns a witness's cosignature line for c at time t. The caller
// is responsible for checking consistency with what it cosigned before.
func Cosign(c Checkpoint, witness *Signer, t time.Time) (string, error) {
	if t.Unix() < 0 {
		return "", errors.New("time before the epoch")
	}
	return witness.cosign(c.Text(), uint64(t.Unix()))
}

// AddCosignatures appends to a signed checkpoint the signature lines from
// lines that are valid cosignatures by witness, ignoring any others, and
// returns the result. It fails if none is valid.
func AddCosignatures(note, lines []byte, operator, witness *Verifier) ([]byte, error) {
	c, err := VerifyCheckpoint(note, operator, nil, 0)
	if err != nil {
		return nil, err
	}
	text := c.Text()
	out := slices.Clone(note)
	added := 0
	for _, line := range strings.SplitAfter(string(lines), "\n") {
		if line == "" {
			continue
		}
		if !strings.HasSuffix(line, "\n") {
			return nil, errors.New("signature line without final newline")
		}
		_, sigs, err := parseNote(append(slices.Clone(text), "\n"+line...))
		if err != nil || len(sigs) != 1 {
			return nil, fmt.Errorf("malformed signature line %q", line)
		}
		s := sigs[0]
		if s.name != witness.name || s.id != witness.id {
			continue
		}
		if err := witness.verify(text, s.sig); err != nil {
			return nil, fmt.Errorf("cosignature by %s: %w", witness.name, err)
		}
		out = append(out, line...)
		added++
	}
	if added == 0 {
		return nil, fmt.Errorf("no cosignature by %s", witness.name)
	}
	return out, nil
}

// VerifyCheckpoint opens a signed checkpoint (spec/checkpoint.md §4). The
// operator's signature must verify, and so must at least quorum of the given
// witnesses' cosignatures.
func VerifyCheckpoint(note []byte, operator *Verifier, witnesses []*Verifier, quorum int) (Checkpoint, error) {
	if operator.Type() != SigEd25519 {
		return Checkpoint{}, errors.New("operator key must be an Ed25519 note key")
	}
	for _, w := range witnesses {
		if w.Type() != SigCosignature {
			return Checkpoint{}, fmt.Errorf("witness key %s is not a cosignature key", w.Name())
		}
	}
	if quorum > len(witnesses) {
		return Checkpoint{}, fmt.Errorf("quorum %d exceeds %d configured witnesses", quorum, len(witnesses))
	}
	text, verified, err := openNote(note, append([]*Verifier{operator}, witnesses...))
	if err != nil {
		return Checkpoint{}, err
	}
	c, err := ParseCheckpoint(text)
	if err != nil {
		return Checkpoint{}, err
	}
	if operator.Name() != c.Origin {
		return Checkpoint{}, fmt.Errorf("operator key %q does not match origin %q", operator.Name(), c.Origin)
	}
	if !slices.Contains(verified, operator) {
		return Checkpoint{}, errors.New("checkpoint is not signed by the operator")
	}
	cosigned := 0
	for _, w := range witnesses {
		if slices.Contains(verified, w) {
			cosigned++
		}
	}
	if cosigned < quorum {
		return Checkpoint{}, fmt.Errorf("%d of %d required witness cosignatures", cosigned, quorum)
	}
	return c, nil
}
