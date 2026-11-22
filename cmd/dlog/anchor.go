package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/eucassoc/deedlog/core"
)

// Anchoring (spec/anchoring.md): the records stay with the operator, and a
// public chain of anchor records commits to them.

func cmdAnchor(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	switch args[0] {
	case "add":
		return cmdAnchorAdd(args[1:], stdout)
	case "prove":
		return cmdAnchorProve(args[1:], stdout)
	case "check":
		return cmdAnchorCheck(args[1:], stdout)
	case "verify":
		return cmdAnchorVerify(args[1:], stdout)
	}
	return errUsage
}

func readLines(path string) (core.Summary, [][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return core.Summary{}, nil, err
	}
	defer f.Close()
	s, lines, err := core.VerifyLines(f)
	if err != nil {
		return s, nil, fmt.Errorf("%s: FAILED: %w", path, err)
	}
	return s, lines, nil
}

func readEntries(path string, missingOK bool) ([]core.AnchorEntry, error) {
	b, err := os.ReadFile(path)
	if missingOK && errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	entries, err := core.ParseAnchorEntries(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return entries, nil
}

// anchorChain is a verified anchor chain and how much of it a verified
// checkpoint covers: all of it when no checkpoint was given.
type anchorChain struct {
	summary    core.Summary
	anchors    []core.AnchorRecord
	covered    uint64
	checkpoint bool
}

// checkpointFlags are the flags that say which checkpoint to trust.
type checkpointFlags struct {
	cp, key   *string
	quorum    *int
	witnesses keyFiles
}

func addCheckpointFlags(fs *flag.FlagSet) *checkpointFlags {
	c := &checkpointFlags{cp: fs.String("checkpoint", "", ""), key: fs.String("key", "", ""), quorum: fs.Int("quorum", 0, "")}
	fs.Var(&c.witnesses, "witness", "")
	return c
}

func readAnchorChain(path string, c *checkpointFlags) (anchorChain, error) {
	if (*c.cp == "") != (*c.key == "") {
		return anchorChain{}, errors.New("-checkpoint and -key must be given together")
	}
	f, err := os.Open(path)
	if err != nil {
		return anchorChain{}, err
	}
	defer f.Close()
	s, leaves, anchors, err := core.VerifyAnchors(f)
	if err != nil {
		return anchorChain{}, fmt.Errorf("%s: FAILED: %w", path, err)
	}
	out := anchorChain{summary: s, anchors: anchors, covered: s.Count}
	if *c.cp == "" {
		return out, nil
	}
	operator, err := readVerifier(*c.key)
	if err != nil {
		return out, err
	}
	var witnesses []*core.Verifier
	for _, p := range c.witnesses {
		w, err := readVerifier(p)
		if err != nil {
			return out, err
		}
		witnesses = append(witnesses, w)
	}
	note, err := os.ReadFile(*c.cp)
	if err != nil {
		return out, err
	}
	cp, err := core.VerifyCheckpoint(note, operator, witnesses, *c.quorum)
	if err != nil {
		return out, fmt.Errorf("%s: FAILED: %w", *c.cp, err)
	}
	if err := core.CheckCheckpoint(s, leaves, cp); err != nil {
		return out, fmt.Errorf("%s: FAILED: %w", path, err)
	}
	out.covered, out.checkpoint = cp.Size, true
	return out, nil
}

func randomHex() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func cmdAnchorAdd(args []string, stdout io.Writer) error {
	fs := newFlags("anchor add")
	recordsPath := fs.String("records", "", "")
	secretsPath := fs.String("secrets", "", "")
	origin := fs.String("origin", "", "")
	epochFlag := fs.String("epoch", "", "")
	rest, err := parse(fs, args, 1)
	if err != nil || *recordsPath == "" || *secretsPath == "" {
		return errUsage
	}
	now := time.Now().UTC().Truncate(time.Second)
	epoch := now
	if *epochFlag != "" {
		if epoch, err = time.Parse(time.RFC3339, *epochFlag); err != nil {
			return fmt.Errorf("-epoch: %w", err)
		}
	}

	entries, err := readEntries(*secretsPath, true)
	if err != nil {
		return err
	}
	var outer core.Summary
	var anchors []core.AnchorRecord
	if _, err := os.Stat(rest[0]); errors.Is(err, os.ErrNotExist) {
		if *origin == "" {
			return fmt.Errorf("%s does not exist; give -origin to start the anchor chain", rest[0])
		}
		if !core.ValidKeyName(*origin) {
			return fmt.Errorf("invalid origin %q", *origin)
		}
	} else {
		none := ""
		ac, err := readAnchorChain(rest[0], &checkpointFlags{cp: &none, key: &none})
		if err != nil {
			return err
		}
		if *origin != "" && *origin != ac.summary.Chain {
			return fmt.Errorf("%s is the anchor chain of %q, not %q", rest[0], ac.summary.Chain, *origin)
		}
		outer, anchors = ac.summary, ac.anchors
	}
	if uint64(len(entries)) != outer.Count {
		return fmt.Errorf("%s has %d entries, %s has %d anchor records", *secretsPath, len(entries), rest[0], outer.Count)
	}
	from := uint64(0)
	if len(entries) > 0 {
		from = entries[len(entries)-1].To
		last, _ := time.Parse(time.RFC3339, anchors[len(anchors)-1].Epoch)
		if !epoch.After(last) {
			return fmt.Errorf("epoch %s does not come after %s, the epoch of the last anchor record", core.FormatEpoch(epoch), anchors[len(anchors)-1].Epoch)
		}
	}

	// An empty record chain is not a chain yet; its first interval is empty.
	var records core.Summary
	var lines [][]byte
	chain := firstNonEmpty(*origin, outer.Chain) + "/records"
	if info, err := os.Stat(*recordsPath); err == nil && info.Size() > 0 {
		if records, lines, err = readLines(*recordsPath); err != nil {
			return err
		}
		chain = records.Chain
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if from > records.Count {
		return fmt.Errorf("%s has %d records, the last anchor record covers up to %d", *recordsPath, records.Count, from)
	}

	entry := core.AnchorEntry{Seq: outer.Count, Epoch: core.FormatEpoch(epoch), From: from, To: records.Count}
	if entry.Nonce, err = randomHex(); err != nil {
		return err
	}
	if entry.Pad, err = randomHex(); err != nil {
		return err
	}
	made, err := core.Anchor(lines[from:], core.AnchorTerms{Chain: chain, Epoch: entry.Epoch, Nonce: entry.Nonce, Pad: entry.Pad})
	if err != nil {
		return err
	}
	entry.Size = made.Size
	name := firstNonEmpty(outer.Chain, *origin)
	line, _, err := core.EventRecord(outer, name, core.Event{
		Source: core.Source{Type: "dlog", ID: name, Collector: "dlog " + version},
		Name:   core.AnchorEvent,
		Meta:   core.AnchorMeta(entry.Epoch, made.Commit),
		At:     now,
	})
	if err != nil {
		return err
	}

	// The secrets first: an anchor record whose secrets are lost can never
	// be checked, while an entry without its record is found by verify.
	b, err := json.MarshalIndent(append(entries, entry), "", "  ")
	if err != nil {
		return err
	}
	tmp := *secretsPath + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, *secretsPath); err != nil {
		return err
	}
	f, err := os.OpenFile(rest[0], os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return printJSON(stdout, struct {
		Chain   string `json:"chain"`
		Records string `json:"records"`
		Seq     uint64 `json:"seq"`
		Epoch   string `json:"epoch"`
		From    uint64 `json:"from"`
		To      uint64 `json:"to"`
		Size    uint64 `json:"size"`
		Commit  string `json:"commit"`
	}{name, chain, entry.Seq, entry.Epoch, entry.From, entry.To, entry.Size, made.Commit})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func cmdAnchorProve(args []string, stdout io.Writer) error {
	fs := newFlags("anchor prove")
	secretsPath := fs.String("secrets", "", "")
	index := fs.Int64("index", -1, "")
	rest, err := parse(fs, args, 1)
	if err != nil || *secretsPath == "" || *index < 0 {
		return errUsage
	}
	s, lines, err := readLines(rest[0])
	if err != nil {
		return err
	}
	entries, err := readEntries(*secretsPath, false)
	if err != nil {
		return err
	}
	i := uint64(*index)
	if i >= s.Count {
		return fmt.Errorf("%s has %d records; there is no record %d", rest[0], s.Count, i)
	}
	for _, e := range entries {
		if i < e.From || i >= e.To || e.To > s.Count {
			continue
		}
		p, err := core.NewRecordProof(lines[e.From:e.To], int(i-e.From), e.Seq,
			core.AnchorTerms{Chain: s.Chain, Epoch: e.Epoch, Nonce: e.Nonce, Pad: e.Pad})
		if err != nil {
			return err
		}
		b, err := json.Marshal(p)
		if err != nil {
			return err
		}
		_, err = stdout.Write(append(b, '\n'))
		return err
	}
	return fmt.Errorf("record %d (line %d of %s) is not anchored yet", i, i+1, rest[0])
}

func cmdAnchorCheck(args []string, stdout io.Writer) error {
	fs := newFlags("anchor check")
	proofPath := fs.String("proof", "", "")
	subjectPath := fs.String("subject", "", "")
	digest := fs.String("digest", "", "")
	recordsChain := fs.String("records-chain", "", "")
	cf := addCheckpointFlags(fs)
	rest, err := parse(fs, args, 1)
	if err != nil || *proofPath == "" || (*subjectPath == "") == (*digest == "") {
		return errUsage
	}
	var subject core.Hash
	if *subjectPath != "" {
		b, err := os.ReadFile(*subjectPath)
		if err != nil {
			return err
		}
		subject = sha256.Sum256(b)
	} else {
		b, err := hex.DecodeString(*digest)
		if err != nil || len(b) != len(subject) {
			return errors.New("-digest is not 64 hexadecimal characters")
		}
		subject = core.Hash(b)
	}
	b, err := os.ReadFile(*proofPath)
	if err != nil {
		return err
	}
	var p core.RecordProof
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("%s: %w", *proofPath, err)
	}
	ac, err := readAnchorChain(rest[0], cf)
	if err != nil {
		return err
	}
	chain := firstNonEmpty(*recordsChain, ac.summary.Chain+"/records")
	if err := core.CheckRecordProof(p, chain, subject, ac.anchors, ac.covered); err != nil {
		return fmt.Errorf("%s: FAILED: %w", *proofPath, err)
	}
	return printJSON(stdout, struct {
		Chain          string  `json:"chain"`
		Records        string  `json:"records"`
		Seq            uint64  `json:"seq"`
		Epoch          string  `json:"epoch"`
		Subject        string  `json:"subject"`
		CheckpointSize *uint64 `json:"checkpoint_size,omitempty"`
	}{ac.summary.Chain, chain, p.Seq, p.Epoch, hex.EncodeToString(subject[:]), ac.checkpointSize()})
}

func (ac anchorChain) checkpointSize() *uint64 {
	if !ac.checkpoint {
		return nil
	}
	return &ac.covered
}

func cmdAnchorVerify(args []string, stdout io.Writer) error {
	fs := newFlags("anchor verify")
	recordsPath := fs.String("records", "", "")
	secretsPath := fs.String("secrets", "", "")
	cf := addCheckpointFlags(fs)
	rest, err := parse(fs, args, 1)
	if err != nil || *recordsPath == "" || *secretsPath == "" {
		return errUsage
	}
	ac, err := readAnchorChain(rest[0], cf)
	if err != nil {
		return err
	}
	entries, err := readEntries(*secretsPath, false)
	if err != nil {
		return err
	}
	f, err := os.Open(*recordsPath)
	if err != nil {
		return err
	}
	defer f.Close()
	a, err := core.CheckAnchored(f, ac.anchors, ac.covered, entries)
	if err != nil {
		var le *core.LineError
		if errors.As(err, &le) {
			return fmt.Errorf("%s: FAILED: %w", *recordsPath, err)
		}
		return fmt.Errorf("FAILED: %w", err)
	}
	return printJSON(stdout, struct {
		core.Anchored
		AnchorChain    string  `json:"anchor_chain"`
		CheckpointSize *uint64 `json:"checkpoint_size,omitempty"`
	}{a, ac.summary.Chain, ac.checkpointSize()})
}
