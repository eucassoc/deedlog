// Package publish serves an operator's chain state for receipt holders and
// verification pages (spec/checkpoint.md §9).
package publish

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/deedlog/deedlog/core"
)

// Handler serves GET /checkpoint and GET /proof from files that the
// operator keeps up to date. Files are read on every request, so the
// operator can replace them at any time.
type Handler struct {
	Chain      string // path of the chain (JSON Lines)
	Checkpoint string // path of the latest signed, cosigned checkpoint
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch r.URL.Path {
	case "/checkpoint":
		note, err := os.ReadFile(h.Checkpoint)
		if err != nil {
			http.Error(w, "checkpoint unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(note)
	case "/proof":
		h.serveProof(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) serveProof(w http.ResponseWriter, r *http.Request) {
	index, err1 := strconv.ParseUint(r.URL.Query().Get("index"), 10, 64)
	size, err2 := strconv.ParseUint(r.URL.Query().Get("size"), 10, 64)
	if err1 != nil || err2 != nil {
		http.Error(w, "index and size are required", http.StatusBadRequest)
		return
	}
	note, err := os.ReadFile(h.Checkpoint)
	if err != nil {
		http.Error(w, "checkpoint unavailable", http.StatusServiceUnavailable)
		return
	}
	latest, err := core.CheckpointOf(note)
	if err != nil {
		http.Error(w, "checkpoint unavailable", http.StatusServiceUnavailable)
		return
	}
	if size > latest.Size || index >= size {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(h.Chain)
	if err != nil {
		http.Error(w, "chain unavailable", http.StatusServiceUnavailable)
		return
	}
	defer f.Close()
	_, leaves, err := core.VerifyLeaves(f)
	if err != nil || uint64(len(leaves)) < size || core.Root(leaves[:latest.Size]) != latest.Root {
		http.Error(w, "chain does not match the published checkpoint", http.StatusInternalServerError)
		return
	}
	proof, _ := core.InclusionProof(leaves[:size], index)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, hash := range append([]core.Hash{leaves[index]}, proof...) {
		fmt.Fprintln(w, base64.StdEncoding.EncodeToString(hash[:]))
	}
}
