// Command dlog works with deedlog evidence chains and checkpoints.
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/eucassoc/deedlog/core"
	"github.com/eucassoc/deedlog/publish"
	"github.com/eucassoc/deedlog/witness"
)

const usage = `usage:
  dlog verify [-checkpoint FILE -key VKEY [-witness VKEY]... [-quorum N]
              [-timestamp TSR [-tsa-roots PEM]]] CHAIN
        verify a chain, and optionally that it matches a signed checkpoint
        and that the checkpoint carries a trusted RFC 3161 time-stamp
  dlog keygen [-witness] -name NAME -out PREFIX
        create PREFIX.key (keep secret) and PREFIX.vkey (publish); NAME is
        the origin for operators, or the witness name with -witness
  dlog checkpoint -key KEY CHAIN
        sign a checkpoint for the chain
  dlog cosign -key VKEY -witness WVKEY=URL [-witness ...] [-quorum N] -out FILE CHAIN CHECKPOINT
        obtain witness cosignatures for a checkpoint (c2sp.org/tlog-witness)
  dlog witness -key WKEY -log VKEY [-log VKEY]... -state FILE [-listen ADDR]
        run a witness for the chains whose operator keys are given
  dlog serve -chain CHAIN -checkpoint FILE [-listen ADDR]
        publish the latest checkpoint and inclusion proofs for receipt holders
  dlog timestamp -tsa URL -out TSR [-tsa-roots PEM] CHECKPOINT
        obtain and verify an RFC 3161 time-stamp for a checkpoint
  dlog prove -index I [-size N] [-leaf] CHAIN
        print an inclusion proof for record I in the tree of size N, preceded
        by the record's leaf hash with -leaf
  dlog prove -old M [-size N] CHAIN
        print a consistency proof from tree size M to N
  dlog misbehavior build -key VKEY CHAIN_A CHECKPOINT_A CHAIN_B CHECKPOINT_B
        build a proof that the operator signed inconsistent checkpoints
  dlog misbehavior check -key VKEY [-receipt-key RVKEY] PROOF
        check a proof of misbehavior
  dlog receipt issue -key RKEY -index I [-url PAGE] CHAIN
        issue a receipt promising that record I stays at index I; with -url,
        print it as a link to the verification page PAGE (for QR codes)
  dlog receipt check -receipt FILE -receipt-key RVKEY -checkpoint FILE -key VKEY
                     [-witness VKEY]... [-quorum N] (-chain CHAIN | -proof FILE) [-out PROOF]
        check a receipt against a checkpoint, using the chain or a proof from
        "dlog prove -leaf"; exit 0 if included, 3 if not yet covered, and 4 if
        the promise is broken, writing a proof of misbehavior to PROOF
  dlog version
        print the version

VKEY and KEY are files containing one key each. N defaults to the chain length.
PEM is a file of trusted TSA root certificates; the system roots are used if
it is omitted.
`

// version is set at build time with -ldflags "-X main.version=...". Without
// it, a binary built by `go install module@version` reports that version.
var version = "dev"

func init() {
	if version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// errUsage reports that the command line was malformed.
var errUsage = errors.New("usage")

// exitStatus is a non-error outcome reported through the exit code.
type exitStatus int

func (e exitStatus) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "verify":
		err = cmdVerify(args[1:], stdout)
	case "keygen":
		err = cmdKeygen(args[1:], stdout)
	case "checkpoint":
		err = cmdCheckpoint(args[1:], stdout)
	case "cosign":
		err = cmdCosign(args[1:], stdout)
	case "witness":
		err = cmdWitness(args[1:], stderr)
	case "serve":
		err = cmdServe(args[1:], stderr)
	case "timestamp":
		err = cmdTimestamp(args[1:], stdout)
	case "prove":
		err = cmdProve(args[1:], stdout)
	case "misbehavior":
		err = cmdMisbehavior(args[1:], stdout)
	case "receipt":
		err = cmdReceipt(args[1:], stdout)
	case "version":
		fmt.Fprintf(stdout, "dlog %s (%s)\n", version, core.SpecVersion)
	default:
		err = errUsage
	}
	var es exitStatus
	switch {
	case errors.As(err, &es):
		return int(es)
	case errors.Is(err, errUsage):
		fmt.Fprint(stderr, usage)
		return 2
	case err != nil:
		fmt.Fprintln(stderr, "dlog:", err)
		return 1
	}
	return 0
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parse(fs *flag.FlagSet, args []string, nargs int) ([]string, error) {
	if err := fs.Parse(args); err != nil || fs.NArg() != nargs {
		return nil, errUsage
	}
	return fs.Args(), nil
}

// keyFiles collects repeated -witness flags.
type keyFiles []string

func (k *keyFiles) String() string     { return strings.Join(*k, ",") }
func (k *keyFiles) Set(v string) error { *k = append(*k, v); return nil }

func readKey(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func readVerifier(path string) (*core.Verifier, error) {
	s, err := readKey(path)
	if err != nil {
		return nil, err
	}
	v, err := core.NewVerifier(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return v, nil
}

func readChain(path string) (core.Summary, []core.Hash, error) {
	f, err := os.Open(path)
	if err != nil {
		return core.Summary{}, nil, err
	}
	defer f.Close()
	s, leaves, err := core.VerifyLeaves(f)
	if err != nil {
		return s, nil, fmt.Errorf("%s: FAILED: %w", path, err)
	}
	return s, leaves, nil
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func cmdVerify(args []string, stdout io.Writer) error {
	fs := newFlags("verify")
	cpPath := fs.String("checkpoint", "", "")
	keyPath := fs.String("key", "", "")
	quorum := fs.Int("quorum", 0, "")
	tsrPath := fs.String("timestamp", "", "")
	rootsPath := fs.String("tsa-roots", "", "")
	var witnessPaths keyFiles
	fs.Var(&witnessPaths, "witness", "")
	rest, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	if (*cpPath == "") != (*keyPath == "") {
		return errors.New("-checkpoint and -key must be given together")
	}
	if *tsrPath != "" && *cpPath == "" {
		return errors.New("-timestamp requires -checkpoint")
	}

	s, leaves, err := readChain(rest[0])
	if err != nil {
		return err
	}
	if *cpPath == "" {
		return printJSON(stdout, s)
	}

	operator, err := readVerifier(*keyPath)
	if err != nil {
		return err
	}
	var witnesses []*core.Verifier
	for _, p := range witnessPaths {
		w, err := readVerifier(p)
		if err != nil {
			return err
		}
		witnesses = append(witnesses, w)
	}
	note, err := os.ReadFile(*cpPath)
	if err != nil {
		return err
	}
	c, err := core.VerifyCheckpoint(note, operator, witnesses, *quorum)
	if err != nil {
		return fmt.Errorf("%s: FAILED: %w", *cpPath, err)
	}
	if err := core.CheckCheckpoint(s, leaves, c); err != nil {
		return fmt.Errorf("%s: FAILED: %w", rest[0], err)
	}
	out := struct {
		core.Summary
		CheckpointSize uint64     `json:"checkpoint_size"`
		Timestamp      *time.Time `json:"timestamp,omitempty"`
		TSA            string     `json:"tsa,omitempty"`
	}{Summary: s, CheckpointSize: c.Size}
	if *tsrPath != "" {
		ts, err := verifyTimestampFile(*tsrPath, c.Text(), *rootsPath)
		if err != nil {
			return err
		}
		out.Timestamp, out.TSA = &ts.Time, tsaName(ts.Signer)
	}
	return printJSON(stdout, out)
}

func readRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil // system roots
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s: no certificates", path)
	}
	return pool, nil
}

func verifyTimestampFile(path string, text []byte, rootsPath string) (*core.Timestamp, error) {
	roots, err := readRoots(rootsPath)
	if err != nil {
		return nil, err
	}
	tsr, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ts, err := core.VerifyTimestamp(tsr, text, roots)
	if err != nil {
		return nil, fmt.Errorf("%s: FAILED: %w", path, err)
	}
	return ts, nil
}

// checkpointText returns the note text of a signed checkpoint without
// verifying its signatures, which is all a time-stamp covers.
func checkpointText(note []byte) ([]byte, error) {
	i := bytes.LastIndex(note, []byte("\n\n"))
	if i < 0 {
		return nil, errors.New("not a signed checkpoint")
	}
	c, err := core.ParseCheckpoint(note[:i+1])
	if err != nil {
		return nil, err
	}
	return c.Text(), nil
}

func cmdTimestamp(args []string, stdout io.Writer) error {
	fs := newFlags("timestamp")
	tsaURL := fs.String("tsa", "", "")
	outPath := fs.String("out", "", "")
	rootsPath := fs.String("tsa-roots", "", "")
	rest, err := parse(fs, args, 1)
	if err != nil || *tsaURL == "" || *outPath == "" {
		return errUsage
	}
	note, err := os.ReadFile(rest[0])
	if err != nil {
		return err
	}
	text, err := checkpointText(note)
	if err != nil {
		return fmt.Errorf("%s: %w", rest[0], err)
	}
	roots, err := readRoots(*rootsPath)
	if err != nil {
		return err
	}
	req, nonce, err := core.TimestampRequest(text)
	if err != nil {
		return err
	}
	tsr, err := postTimestampRequest(*tsaURL, req)
	if err != nil {
		return err
	}
	ts, err := core.VerifyTimestamp(tsr, text, roots)
	if err != nil {
		return fmt.Errorf("response from %s: %w", *tsaURL, err)
	}
	if ts.Nonce == nil || ts.Nonce.Cmp(nonce) != 0 {
		return fmt.Errorf("response from %s does not carry the request nonce", *tsaURL)
	}
	if err := writeNew(*outPath, string(tsr), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s\t%s\n", ts.Time.UTC().Format(time.RFC3339), tsaName(ts.Signer))
	return nil
}

// tsaName returns a short name for a TSA certificate.
func tsaName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

func postTimestampRequest(url string, req []byte) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(url, "application/timestamp-query", bytes.NewReader(req))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func cmdKeygen(args []string, stdout io.Writer) error {
	fs := newFlags("keygen")
	name := fs.String("name", "", "")
	out := fs.String("out", "", "")
	isWitness := fs.Bool("witness", false, "")
	if _, err := parse(fs, args, 0); err != nil || *name == "" || *out == "" {
		return errUsage
	}
	generate := core.GenerateKey
	if *isWitness {
		generate = core.GenerateWitnessKey
	}
	skey, vkey, err := generate(*name)
	if err != nil {
		return err
	}
	if err := writeNew(*out+".key", skey+"\n", 0o600); err != nil {
		return err
	}
	if err := writeNew(*out+".vkey", vkey+"\n", 0o644); err != nil {
		return err
	}
	fmt.Fprintln(stdout, vkey)
	return nil
}

// writeNew writes a file that must not already exist.
func writeNew(path, content string, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func cmdCheckpoint(args []string, stdout io.Writer) error {
	fs := newFlags("checkpoint")
	keyPath := fs.String("key", "", "")
	rest, err := parse(fs, args, 1)
	if err != nil || *keyPath == "" {
		return errUsage
	}
	skey, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	signer, err := core.NewSigner(skey)
	if err != nil {
		return fmt.Errorf("%s: %w", *keyPath, err)
	}
	s, leaves, err := readChain(rest[0])
	if err != nil {
		return err
	}
	note, err := core.SignCheckpoint(core.Checkpoint{Origin: s.Chain, Size: s.Count, Root: core.Root(leaves)}, signer)
	if err != nil {
		return err
	}
	_, err = stdout.Write(note)
	return err
}

func cmdProve(args []string, stdout io.Writer) error {
	fs := newFlags("prove")
	index := fs.Int64("index", -1, "")
	old := fs.Int64("old", -1, "")
	size := fs.Int64("size", -1, "")
	withLeaf := fs.Bool("leaf", false, "")
	rest, err := parse(fs, args, 1)
	if err != nil || (*index < 0) == (*old < 0) {
		return errUsage
	}
	_, leaves, err := readChain(rest[0])
	if err != nil {
		return err
	}
	n := int64(len(leaves))
	if *size >= 0 {
		if *size > n {
			return fmt.Errorf("size %d exceeds chain length %d", *size, n)
		}
		n = *size
	}
	var proof []core.Hash
	if *index >= 0 {
		proof, err = core.InclusionProof(leaves[:n], uint64(*index))
		if err == nil && *withLeaf {
			proof = append([]core.Hash{leaves[*index]}, proof...)
		}
	} else if *withLeaf {
		return errUsage
	} else {
		proof, err = core.ConsistencyProof(leaves[:n], uint64(*old))
	}
	if err != nil {
		return err
	}
	for _, h := range proof {
		fmt.Fprintln(stdout, base64.StdEncoding.EncodeToString(h[:]))
	}
	return nil
}

func cmdMisbehavior(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	fs := newFlags("misbehavior")
	keyPath := fs.String("key", "", "")
	switch args[0] {
	case "build":
		rest, err := parse(fs, args[1:], 4)
		if err != nil || *keyPath == "" {
			return errUsage
		}
		operator, err := readVerifier(*keyPath)
		if err != nil {
			return err
		}
		_, leavesA, err := readChain(rest[0])
		if err != nil {
			return err
		}
		noteA, err := os.ReadFile(rest[1])
		if err != nil {
			return err
		}
		_, leavesB, err := readChain(rest[2])
		if err != nil {
			return err
		}
		noteB, err := os.ReadFile(rest[3])
		if err != nil {
			return err
		}
		p, err := core.BuildMisbehaviorProof(noteA, leavesA, noteB, leavesB, operator)
		if err != nil {
			return err
		}
		return printJSON(stdout, p)
	case "check":
		receiptKeyPath := fs.String("receipt-key", "", "")
		rest, err := parse(fs, args[1:], 1)
		if err != nil || *keyPath == "" {
			return errUsage
		}
		operator, err := readVerifier(*keyPath)
		if err != nil {
			return err
		}
		var receiptKey *core.Verifier
		if *receiptKeyPath != "" {
			if receiptKey, err = readVerifier(*receiptKeyPath); err != nil {
				return err
			}
		}
		b, err := os.ReadFile(rest[0])
		if err != nil {
			return err
		}
		var p core.MisbehaviorProof
		if err := json.Unmarshal(b, &p); err != nil {
			return fmt.Errorf("%s: %w", rest[0], err)
		}
		desc, err := core.CheckMisbehavior(p, operator, receiptKey)
		if err != nil {
			return fmt.Errorf("%s: not a proof of misbehavior: %w", rest[0], err)
		}
		fmt.Fprintln(stdout, "MISBEHAVIOR PROVEN:", desc)
		return nil
	default:
		return errUsage
	}
}

func cmdCosign(args []string, stdout io.Writer) error {
	fs := newFlags("cosign")
	keyPath := fs.String("key", "", "")
	outPath := fs.String("out", "", "")
	quorum := fs.Int("quorum", 1, "")
	var specs keyFiles
	fs.Var(&specs, "witness", "")
	rest, err := parse(fs, args, 2)
	if err != nil || *keyPath == "" || *outPath == "" || len(specs) == 0 {
		return errUsage
	}
	operator, err := readVerifier(*keyPath)
	if err != nil {
		return err
	}
	var witnesses []witness.Witness
	for _, spec := range specs {
		path, url, ok := strings.Cut(spec, "=")
		if !ok || url == "" {
			return fmt.Errorf("-witness %q: want VKEYFILE=URL", spec)
		}
		key, err := readVerifier(path)
		if err != nil {
			return err
		}
		witnesses = append(witnesses, witness.Witness{Key: key, URL: url})
	}
	_, leaves, err := readChain(rest[0])
	if err != nil {
		return err
	}
	note, err := os.ReadFile(rest[1])
	if err != nil {
		return err
	}

	client := &witness.Client{HTTP: &http.Client{Timeout: 30 * time.Second}}
	out := bytes.Clone(note)
	cosigned := 0
	for _, w := range witnesses {
		got, err := client.Cosign(context.Background(), w, note, leaves, operator, 0)
		if err != nil {
			fmt.Fprintf(stdout, "%s\tFAILED: %v\n", w.Key.Name(), err)
			continue
		}
		out = append(out, got[len(note):]...)
		cosigned++
		fmt.Fprintf(stdout, "%s\tcosigned\n", w.Key.Name())
	}
	if cosigned < *quorum {
		return fmt.Errorf("%d of %d required cosignatures", cosigned, *quorum)
	}
	return writeNew(*outPath, string(out), 0o644)
}

func cmdWitness(args []string, stderr io.Writer) error {
	srv, addr, err := newWitnessServer(args)
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "witness %s listening on %s\n", srv.Signer.Name(), addr)
	mux := http.NewServeMux()
	mux.Handle("POST /add-checkpoint", srv)
	return (&http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}).ListenAndServe()
}

func newWitnessServer(args []string) (*witness.Server, string, error) {
	fs := newFlags("witness")
	keyPath := fs.String("key", "", "")
	statePath := fs.String("state", "", "")
	listen := fs.String("listen", "localhost:8080", "")
	var logPaths keyFiles
	fs.Var(&logPaths, "log", "")
	if _, err := parse(fs, args, 0); err != nil || *keyPath == "" || *statePath == "" || len(logPaths) == 0 {
		return nil, "", errUsage
	}
	skey, err := readKey(*keyPath)
	if err != nil {
		return nil, "", err
	}
	signer, err := core.NewSigner(skey)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", *keyPath, err)
	}
	if signer.Type() != core.SigCosignature {
		return nil, "", fmt.Errorf("%s: not a witness key (create one with dlog keygen -witness)", *keyPath)
	}
	logs := make(map[string]*core.Verifier)
	for _, p := range logPaths {
		v, err := readVerifier(p)
		if err != nil {
			return nil, "", err
		}
		logs[v.Name()] = v
	}
	store, err := witness.OpenFileStore(*statePath)
	if err != nil {
		return nil, "", err
	}
	return &witness.Server{Signer: signer, Logs: logs, Store: store}, *listen, nil
}

func cmdReceipt(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	switch args[0] {
	case "issue":
		return cmdReceiptIssue(args[1:], stdout)
	case "check":
		return cmdReceiptCheck(args[1:], stdout)
	}
	return errUsage
}

func cmdReceiptIssue(args []string, stdout io.Writer) error {
	fs := newFlags("receipt issue")
	keyPath := fs.String("key", "", "")
	index := fs.Int64("index", -1, "")
	page := fs.String("url", "", "")
	rest, err := parse(fs, args, 1)
	if err != nil || *keyPath == "" || *index < 0 {
		return errUsage
	}
	skey, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	signer, err := core.NewSigner(skey)
	if err != nil {
		return fmt.Errorf("%s: %w", *keyPath, err)
	}
	s, leaves, err := readChain(rest[0])
	if err != nil {
		return err
	}
	if *index >= int64(len(leaves)) {
		return fmt.Errorf("chain has no record %d", *index)
	}
	note, err := core.IssueReceipt(core.Receipt{Origin: s.Chain, Index: uint64(*index), LeafHash: leaves[*index]}, signer)
	if err != nil {
		return err
	}
	if *page != "" {
		_, err = fmt.Fprintln(stdout, core.ReceiptURL(*page, note))
		return err
	}
	_, err = stdout.Write(note)
	return err
}

func cmdReceiptCheck(args []string, stdout io.Writer) error {
	fs := newFlags("receipt check")
	receiptPath := fs.String("receipt", "", "")
	receiptKeyPath := fs.String("receipt-key", "", "")
	cpPath := fs.String("checkpoint", "", "")
	keyPath := fs.String("key", "", "")
	quorum := fs.Int("quorum", 0, "")
	chainPath := fs.String("chain", "", "")
	proofPath := fs.String("proof", "", "")
	outPath := fs.String("out", "", "")
	var witnessPaths keyFiles
	fs.Var(&witnessPaths, "witness", "")
	if _, err := parse(fs, args, 0); err != nil || *receiptPath == "" || *receiptKeyPath == "" ||
		*cpPath == "" || *keyPath == "" || (*chainPath == "") == (*proofPath == "") {
		return errUsage
	}

	receiptKey, err := readVerifier(*receiptKeyPath)
	if err != nil {
		return err
	}
	receiptNote, err := os.ReadFile(*receiptPath)
	if err != nil {
		return err
	}
	r, err := core.VerifyReceipt(receiptNote, receiptKey)
	if err != nil {
		return fmt.Errorf("%s: FAILED: %w", *receiptPath, err)
	}
	operator, err := readVerifier(*keyPath)
	if err != nil {
		return err
	}
	var witnesses []*core.Verifier
	for _, p := range witnessPaths {
		w, err := readVerifier(p)
		if err != nil {
			return err
		}
		witnesses = append(witnesses, w)
	}
	cpNote, err := os.ReadFile(*cpPath)
	if err != nil {
		return err
	}
	c, err := core.VerifyCheckpoint(cpNote, operator, witnesses, *quorum)
	if err != nil {
		return fmt.Errorf("%s: FAILED: %w", *cpPath, err)
	}

	var leaf core.Hash
	var proof []core.Hash
	if r.Index < c.Size {
		if *chainPath != "" {
			s, leaves, err := readChain(*chainPath)
			if err != nil {
				return err
			}
			if err := core.CheckCheckpoint(s, leaves, c); err != nil {
				return fmt.Errorf("%s: FAILED: %w", *chainPath, err)
			}
			leaf = leaves[r.Index]
			proof, _ = core.InclusionProof(leaves[:c.Size], r.Index)
		} else {
			hashes, err := readHashLines(*proofPath)
			if err != nil {
				return err
			}
			if len(hashes) == 0 {
				return fmt.Errorf("%s: empty proof", *proofPath)
			}
			leaf, proof = hashes[0], hashes[1:]
		}
	}

	status, mp, err := core.CheckReceipt(receiptNote, r, cpNote, c, leaf, proof)
	if err != nil {
		return err
	}
	switch status {
	case core.ReceiptIncluded:
		fmt.Fprintf(stdout, "INCLUDED: record %d of %s is in the checkpoint of size %d\n", r.Index, r.Origin, c.Size)
		return nil
	case core.ReceiptNotYetCovered:
		fmt.Fprintf(stdout, "NOT YET COVERED: record %d of %s, checkpoint size %d\n", r.Index, r.Origin, c.Size)
		return exitStatus(3)
	}
	desc, err := core.CheckMisbehavior(*mp, operator, receiptKey)
	if err != nil {
		return fmt.Errorf("internal error: built an invalid proof: %w", err)
	}
	fmt.Fprintln(stdout, "MISBEHAVIOR PROVEN:", desc)
	if *outPath != "" {
		b, err := json.MarshalIndent(mp, "", "  ")
		if err != nil {
			return err
		}
		if err := writeNew(*outPath, string(b)+"\n", 0o644); err != nil {
			return err
		}
	}
	return exitStatus(4)
}

func readHashLines(path string) ([]core.Hash, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var hashes []core.Hash
	for _, line := range strings.Fields(string(b)) {
		h, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(h) != len(core.Hash{}) {
			return nil, fmt.Errorf("%s: invalid hash %q", path, line)
		}
		hashes = append(hashes, core.Hash(h))
	}
	return hashes, nil
}

func cmdServe(args []string, stderr io.Writer) error {
	fs := newFlags("serve")
	chain := fs.String("chain", "", "")
	cp := fs.String("checkpoint", "", "")
	listen := fs.String("listen", "localhost:8081", "")
	if _, err := parse(fs, args, 0); err != nil || *chain == "" || *cp == "" {
		return errUsage
	}
	fmt.Fprintf(stderr, "publishing %s on %s\n", *cp, *listen)
	h := &publish.Handler{Chain: *chain, Checkpoint: *cp}
	return (&http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 10 * time.Second}).ListenAndServe()
}
