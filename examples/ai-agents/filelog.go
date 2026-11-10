package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/eucassoc/deedlog/core"
	"github.com/eucassoc/deedlog/examples/internal/demo"
)

// FileLog appends records to a chain file with core.Writer, resuming the
// chain if the file exists. This is all a product needs to start recording;
// checkpoints are made separately, for example with dlog checkpoint and
// dlog cosign on a schedule.
type FileLog struct {
	Origin string
	// First is recorded before anything else when the chain is created,
	// such as the agent's declared policy.
	First *demo.Event
	Now   func() time.Time

	path string
	key  []byte
}

// OpenFileLog prepares to record into the chain at path, which is created
// on the first record. The HMAC key is read from keyPath, which is created
// if missing.
func OpenFileLog(path, origin, keyPath string) (*FileLog, error) {
	key, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else if key, err = hex.DecodeString(strings.TrimSpace(string(key))); err != nil {
		return nil, fmt.Errorf("%s: %w", keyPath, err)
	}
	return &FileLog{Origin: origin, Now: time.Now, path: path, key: key}, nil
}

// Record appends one record. Several processes, such as hooks running in
// parallel, may append to the same chain; a lock file serializes them.
func (l *FileLog) Record(e demo.Event) error {
	unlock, err := lock(l.path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()

	f, err := os.OpenFile(l.path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	existing, err := os.ReadFile(l.path)
	if err != nil {
		return err
	}
	var w *core.Writer
	if len(existing) == 0 {
		w, err = core.NewWriter(f, l.Origin)
	} else {
		var s core.Summary
		if s, err = core.Verify(bytes.NewReader(existing)); err != nil {
			return fmt.Errorf("%s: %w", l.path, err)
		}
		if s.Chain != l.Origin {
			return fmt.Errorf("%s is chain %q, not %q", l.path, s.Chain, l.Origin)
		}
		w, err = core.ResumeWriter(f, s)
	}
	if err != nil {
		return err
	}
	events := []demo.Event{e}
	if len(existing) == 0 && l.First != nil {
		events = []demo.Event{*l.First, e}
	}
	for _, e := range events {
		alg, digest := "sha256", demo.Sum(e.Body)
		if e.Keyed {
			m := hmac.New(sha256.New, l.key)
			m.Write(e.Body)
			alg, digest = "hmac-sha256", hex.EncodeToString(m.Sum(nil))
		}
		if _, err := w.Append(core.Record{
			CollectedAt: l.Now(),
			Source:      e.Source,
			Subject:     core.Subject{MediaType: e.MediaType, Size: int64(len(e.Body)), Digest: map[string]string{alg: digest}},
			Meta:        e.Meta,
		}); err != nil {
			return err
		}
	}
	return f.Sync()
}

// lock takes an exclusive lock file, waiting up to five seconds. A lock
// older than a minute is considered left behind by a crashed process.
func lock(path string) (func(), error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) > time.Minute {
			os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("chain is locked by %s", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
