package witness

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eucassoc/deedlog/core"
)

// Store keeps the latest cosigned checkpoint for each origin.
type Store interface {
	// Latest returns the latest cosigned checkpoint for origin, or ok false.
	Latest(origin string) (c core.Checkpoint, ok bool, err error)
	// Put records c as the latest cosigned checkpoint for its origin.
	Put(c core.Checkpoint) error
}

// MemoryStore is a Store held in memory.
type MemoryStore struct {
	mu sync.Mutex
	m  map[string]core.Checkpoint
}

func (s *MemoryStore) Latest(origin string) (core.Checkpoint, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.m[origin]
	return c, ok, nil
}

func (s *MemoryStore) Put(c core.Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = make(map[string]core.Checkpoint)
	}
	s.m[c.Origin] = c
	return nil
}

// Server is a witness implementing add-checkpoint of c2sp.org/tlog-witness.
type Server struct {
	Signer *core.Signer              // the witness's cosignature key
	Logs   map[string]*core.Verifier // operator keys by origin
	Store  Store
	Now    func() time.Time // time.Now if nil

	mu sync.Mutex // serializes check-and-update, as the protocol requires
}

// ServeHTTP handles POST .../add-checkpoint.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/add-checkpoint") {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "cannot read request", http.StatusBadRequest)
		return
	}
	status, resp := s.addCheckpoint(body)
	if status == http.StatusConflict {
		w.Header().Set("Content-Type", "text/x.tlog.size")
	}
	w.WriteHeader(status)
	w.Write(resp)
}

func (s *Server) addCheckpoint(body []byte) (int, []byte) {
	oldSize, proof, note, err := parseAddCheckpoint(body)
	if err != nil {
		return http.StatusBadRequest, []byte(err.Error() + "\n")
	}
	origin, err := noteOrigin(note)
	if err != nil {
		return http.StatusBadRequest, []byte(err.Error() + "\n")
	}
	operator, ok := s.Logs[origin]
	if !ok {
		return http.StatusNotFound, []byte("unknown origin\n")
	}
	c, err := core.VerifyCheckpoint(note, operator, nil, 0)
	if err != nil {
		return http.StatusForbidden, []byte(err.Error() + "\n")
	}
	if oldSize > c.Size {
		return http.StatusBadRequest, []byte("old size larger than checkpoint size\n")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	latest, have, err := s.Store.Latest(origin)
	if err != nil {
		return http.StatusInternalServerError, nil
	}
	if !have {
		latest = core.Checkpoint{Origin: origin, Size: 0, Root: core.EmptyRoot}
	}
	if oldSize != latest.Size {
		return http.StatusConflict, fmt.Appendf(nil, "%d\n", latest.Size)
	}
	if oldSize == 0 && len(proof) != 0 {
		return http.StatusUnprocessableEntity, []byte("proof from size 0 must be empty\n")
	}
	if err := core.VerifyConsistency(latest.Size, c.Size, latest.Root, c.Root, proof); err != nil {
		return http.StatusUnprocessableEntity, []byte(err.Error() + "\n")
	}
	if err := s.Store.Put(c); err != nil {
		return http.StatusInternalServerError, nil
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	line, err := core.Cosign(c, s.Signer, now())
	if err != nil {
		return http.StatusInternalServerError, nil
	}
	return http.StatusOK, []byte(line)
}

func parseAddCheckpoint(body []byte) (uint64, []core.Hash, []byte, error) {
	header, note, ok := bytes.Cut(body, []byte("\n\n"))
	if !ok {
		return 0, nil, nil, errors.New("missing empty line before checkpoint")
	}
	sc := bufio.NewScanner(bytes.NewReader(append(header, '\n')))
	if !sc.Scan() {
		return 0, nil, nil, errors.New("missing old size line")
	}
	sizeStr, ok := strings.CutPrefix(sc.Text(), "old ")
	oldSize, err := strconv.ParseUint(sizeStr, 10, 64)
	if !ok || err != nil || strconv.FormatUint(oldSize, 10) != sizeStr {
		return 0, nil, nil, errors.New("malformed old size line")
	}
	var proof []core.Hash
	for sc.Scan() {
		b, err := base64.StdEncoding.DecodeString(sc.Text())
		if err != nil || len(b) != len(core.Hash{}) || base64.StdEncoding.EncodeToString(b) != sc.Text() {
			return 0, nil, nil, errors.New("malformed consistency proof line")
		}
		proof = append(proof, core.Hash(b))
	}
	if len(proof) > maxProofLines {
		return 0, nil, nil, errors.New("too many consistency proof lines")
	}
	return oldSize, proof, note, nil
}

func noteOrigin(note []byte) (string, error) {
	origin, _, ok := bytes.Cut(note, []byte("\n"))
	if !ok || !core.ValidKeyName(string(origin)) {
		return "", errors.New("malformed checkpoint")
	}
	return string(origin), nil
}

// FileStore is a Store persisted to a file, one checkpoint note text per
// origin. Writes replace the file atomically.
type FileStore struct {
	path string
	mem  MemoryStore
}

// OpenFileStore loads a FileStore from path, which need not exist yet.
func OpenFileStore(path string) (*FileStore, error) {
	s := &FileStore{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	for _, text := range bytes.Split(b, []byte("\n\n")) {
		if len(bytes.TrimSpace(text)) == 0 {
			continue
		}
		c, err := core.ParseCheckpoint(append(bytes.TrimRight(text, "\n"), '\n'))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		s.mem.Put(c)
	}
	return s, nil
}

func (s *FileStore) Latest(origin string) (core.Checkpoint, bool, error) {
	return s.mem.Latest(origin)
}

func (s *FileStore) Put(c core.Checkpoint) error {
	s.mem.mu.Lock()
	next := maps.Clone(s.mem.m)
	s.mem.mu.Unlock()
	if next == nil {
		next = make(map[string]core.Checkpoint)
	}
	next[c.Origin] = c
	var b bytes.Buffer
	for _, origin := range slices.Sorted(maps.Keys(next)) {
		b.Write(next[origin].Text())
		b.WriteByte('\n')
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b.Bytes(), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	return s.mem.Put(c)
}
