// Package witness implements the c2sp.org/tlog-witness protocol for
// deedlog checkpoints: a client that obtains cosignatures for an
// operator, and a witness server (spec/checkpoint.md §4).
package witness

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/eucassoc/deedlog/core"
)

// maxProofLines is the limit on consistency proof lines in add-checkpoint.
const maxProofLines = 63

// Witness identifies a witness by its verifier key and submission prefix.
type Witness struct {
	Key *core.Verifier
	URL string
}

// Errors returned by Cosign for specific witness responses.
var (
	// ErrUnknownLog means the witness is not configured for the origin.
	ErrUnknownLog = errors.New("witness does not know this origin")
	// ErrInconsistent means the witness holds a checkpoint that the chain is
	// not consistent with. Do not retry with a different history.
	ErrInconsistent = errors.New("witness rejected the consistency proof: the chain is not consistent with the checkpoint the witness cosigned before")
	// ErrStale means the witness has already cosigned a larger tree.
	ErrStale = errors.New("witness has already cosigned a larger tree")
)

// Client submits checkpoints to witnesses.
type Client struct {
	HTTP *http.Client // http.DefaultClient if nil
}

// Cosign submits a signed checkpoint, for a chain with the given leaf
// hashes, to w and returns the checkpoint with w's cosignatures appended.
// oldSize is the size the caller last saw w cosign, or 0 if unknown.
func (cl *Client) Cosign(ctx context.Context, w Witness, note []byte, leaves []core.Hash, operator *core.Verifier, oldSize uint64) ([]byte, error) {
	c, err := core.VerifyCheckpoint(note, operator, nil, 0)
	if err != nil {
		return nil, err
	}
	if uint64(len(leaves)) < c.Size || core.Root(leaves[:c.Size]) != c.Root {
		return nil, errors.New("chain does not match the checkpoint")
	}
	leaves = leaves[:c.Size]

	for attempt := 0; attempt < 2; attempt++ {
		if oldSize > c.Size {
			return nil, fmt.Errorf("%w (%d > %d)", ErrStale, oldSize, c.Size)
		}
		proof, err := core.ConsistencyProof(leaves, oldSize)
		if err != nil {
			return nil, err
		}
		if len(proof) > maxProofLines {
			return nil, errors.New("consistency proof too long")
		}
		body := fmt.Appendf(nil, "old %d\n", oldSize)
		for _, h := range proof {
			body = fmt.Appendf(body, "%s\n", base64.StdEncoding.EncodeToString(h[:]))
		}
		body = append(append(body, '\n'), note...)

		status, resp, err := cl.post(ctx, strings.TrimSuffix(w.URL, "/")+"/add-checkpoint", body)
		if err != nil {
			return nil, err
		}
		switch status {
		case http.StatusOK:
			return core.AddCosignatures(note, resp, operator, w.Key)
		case http.StatusConflict:
			size, err := strconv.ParseUint(strings.TrimSuffix(string(resp), "\n"), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("witness returned a malformed size %q", resp)
			}
			oldSize = size
			continue
		case http.StatusNotFound:
			return nil, ErrUnknownLog
		case http.StatusForbidden:
			return nil, errors.New("witness rejected the operator signature")
		case http.StatusUnprocessableEntity:
			return nil, ErrInconsistent
		default:
			return nil, fmt.Errorf("witness responded %d: %s", status, bytes.TrimSpace(resp))
		}
	}
	return nil, errors.New("witness kept reporting a conflicting size")
}

func (cl *Client) post(ctx context.Context, url string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	hc := cl.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, b, nil
}
