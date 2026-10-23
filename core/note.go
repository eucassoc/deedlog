package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Signature types of c2sp.org/signed-note.
const (
	SigEd25519     byte = 0x01 // Ed25519 note signature, used by operators
	SigCosignature byte = 0x04 // timestamped Ed25519 checkpoint cosignature, used by witnesses
)

const sigPrefix = "— " // em dash and space

// ValidKeyName reports whether name may be used as a note key name, a
// cosigner name or a checkpoint origin (c2sp.org/tlog-cosignature).
func ValidKeyName(name string) bool {
	if name == "" || len(name) > 255 || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == '+' || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func keyID(name string, typ byte, pub []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', typ})
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil))
}

// decodeBase64 rejects non-canonical encodings, as C2SP requires.
func decodeBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, fmt.Errorf("invalid base64 %q", s)
	}
	return b, nil
}

// GenerateKey returns a new Ed25519 note signing key, as used by operators
// to sign checkpoints, and the matching verifier key, both encoded as text.
func GenerateKey(name string) (skey, vkey string, err error) {
	return generateKey(name, SigEd25519)
}

// GenerateWitnessKey returns a new key for Ed25519 checkpoint cosignatures
// (c2sp.org/tlog-cosignature), as used by witnesses, and the matching
// verifier key.
func GenerateWitnessKey(name string) (skey, vkey string, err error) {
	return generateKey(name, SigCosignature)
}

func generateKey(name string, typ byte) (skey, vkey string, err error) {
	if !ValidKeyName(name) {
		return "", "", fmt.Errorf("invalid key name %q", name)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	id := keyID(name, typ, pub)
	skey = fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", name, id,
		base64.StdEncoding.EncodeToString(append([]byte{typ}, priv.Seed()...)))
	vkey = fmt.Sprintf("%s+%08x+%s", name, id,
		base64.StdEncoding.EncodeToString(append([]byte{typ}, pub...)))
	return skey, vkey, nil
}

// Signer signs notes, or cosigns checkpoints, with an Ed25519 key.
type Signer struct {
	name string
	id   uint32
	typ  byte
	key  ed25519.PrivateKey
}

// NewSigner parses a signer key produced by GenerateKey.
func NewSigner(skey string) (*Signer, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(skey), "PRIVATE+KEY+")
	if !ok {
		return nil, errors.New("not a signer key")
	}
	name, id, typ, material, err := parseKey(rest)
	if err != nil {
		return nil, err
	}
	if (typ != SigEd25519 && typ != SigCosignature) || len(material) != ed25519.SeedSize {
		return nil, errors.New("signer key is not an Ed25519 note or cosignature key")
	}
	priv := ed25519.NewKeyFromSeed(material)
	if keyID(name, typ, priv.Public().(ed25519.PublicKey)) != id {
		return nil, errors.New("signer key ID does not match key")
	}
	return &Signer{name: name, id: id, typ: typ, key: priv}, nil
}

// Name returns the key name.
func (s *Signer) Name() string { return s.name }

// Type returns the signature type.
func (s *Signer) Type() byte { return s.typ }

// Verifier returns the verifier for this signer's signatures.
func (s *Signer) Verifier() *Verifier {
	return &Verifier{name: s.name, id: s.id, typ: s.typ, pub: s.key.Public().(ed25519.PublicKey)}
}

func (s *Signer) signatureLine(sig []byte) string {
	b := binary.BigEndian.AppendUint32(nil, s.id)
	return sigPrefix + s.name + " " + base64.StdEncoding.EncodeToString(append(b, sig...)) + "\n"
}

// Sign returns text followed by a signature line. text must end with a
// newline. Only note signing keys can sign.
func (s *Signer) Sign(text []byte) ([]byte, error) {
	if s.typ != SigEd25519 {
		return nil, errors.New("cosignature keys cannot sign notes")
	}
	if err := checkNoteText(text); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.Write(text)
	b.WriteString("\n" + s.signatureLine(ed25519.Sign(s.key, text)))
	return b.Bytes(), nil
}

// cosign returns a c2sp.org/tlog-cosignature Ed25519 cosignature line over
// checkpoint note text.
func (s *Signer) cosign(text []byte, ts uint64) (string, error) {
	if s.typ != SigCosignature {
		return "", errors.New("only cosignature keys can cosign")
	}
	msg := append([]byte("cosignature/v1\ntime "+strconv.FormatUint(ts, 10)+"\n"), text...)
	sig := binary.BigEndian.AppendUint64(nil, ts)
	return s.signatureLine(append(sig, ed25519.Sign(s.key, msg)...)), nil
}

// Verifier checks note signatures from one key.
type Verifier struct {
	name string
	id   uint32
	typ  byte
	pub  ed25519.PublicKey
}

// NewVerifier parses a verifier key ("vkey") of type 0x01 or 0x04.
func NewVerifier(vkey string) (*Verifier, error) {
	name, id, typ, material, err := parseKey(strings.TrimSpace(vkey))
	if err != nil {
		return nil, err
	}
	if typ != SigEd25519 && typ != SigCosignature {
		return nil, fmt.Errorf("unsupported signature type 0x%02x", typ)
	}
	if len(material) != ed25519.PublicKeySize {
		return nil, errors.New("verifier key is not an Ed25519 public key")
	}
	if keyID(name, typ, material) != id {
		return nil, errors.New("verifier key ID does not match key")
	}
	return &Verifier{name: name, id: id, typ: typ, pub: material}, nil
}

// Name returns the key name.
func (v *Verifier) Name() string { return v.name }

// Type returns the signature type.
func (v *Verifier) Type() byte { return v.typ }

func (v *Verifier) verify(text, sig []byte) error {
	switch v.typ {
	case SigEd25519:
		if !ed25519.Verify(v.pub, text, sig) {
			return errors.New("invalid signature")
		}
	case SigCosignature:
		if len(sig) != 8+ed25519.SignatureSize {
			return errors.New("invalid cosignature length")
		}
		ts := binary.BigEndian.Uint64(sig)
		msg := append([]byte("cosignature/v1\ntime "+strconv.FormatUint(ts, 10)+"\n"), text...)
		if !ed25519.Verify(v.pub, msg, sig[8:]) {
			return errors.New("invalid cosignature")
		}
	}
	return nil
}

func parseKey(s string) (name string, id uint32, typ byte, material []byte, err error) {
	// Key names and IDs contain no "+", but base64 key material may.
	parts := strings.SplitN(s, "+", 3)
	if len(parts) != 3 {
		return "", 0, 0, nil, errors.New("malformed key")
	}
	name = parts[0]
	if !ValidKeyName(name) {
		return "", 0, 0, nil, fmt.Errorf("invalid key name %q", name)
	}
	idBytes, err := hex.DecodeString(parts[1])
	if err != nil || len(idBytes) != 4 || strings.ToLower(parts[1]) != parts[1] {
		return "", 0, 0, nil, errors.New("malformed key ID")
	}
	key, err := decodeBase64(parts[2])
	if err != nil || len(key) < 2 {
		return "", 0, 0, nil, errors.New("malformed key material")
	}
	return name, binary.BigEndian.Uint32(idBytes), key[0], key[1:], nil
}

// noteSignature is one signature line of a note.
type noteSignature struct {
	name string
	id   uint32
	sig  []byte
}

func checkNoteText(text []byte) error {
	if len(text) == 0 || text[len(text)-1] != '\n' {
		return errors.New("note text must end with a newline")
	}
	if !utf8.Valid(text) {
		return errors.New("note is not valid UTF-8")
	}
	for _, c := range text {
		if c < 0x20 && c != '\n' {
			return errors.New("note contains a control character")
		}
	}
	return nil
}

// parseNote splits a signed note into its text and signatures.
func parseNote(note []byte) ([]byte, []noteSignature, error) {
	if err := checkNoteText(note); err != nil {
		return nil, nil, err
	}
	i := bytes.LastIndex(note, []byte("\n\n"))
	if i < 0 {
		return nil, nil, errors.New("note has no signatures")
	}
	text, block := note[:i+1], note[i+2:]
	if len(block) == 0 {
		return nil, nil, errors.New("note has no signatures")
	}
	var sigs []noteSignature
	for _, line := range strings.SplitAfter(string(block), "\n") {
		if line == "" {
			continue
		}
		rest, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), sigPrefix)
		if !ok {
			return nil, nil, fmt.Errorf("malformed signature line %q", line)
		}
		name, b64, ok := strings.Cut(rest, " ")
		if !ok || !ValidKeyName(name) {
			return nil, nil, fmt.Errorf("malformed signature line %q", line)
		}
		sig, err := decodeBase64(b64)
		if err != nil || len(sig) < 4 {
			return nil, nil, fmt.Errorf("malformed signature line %q", line)
		}
		sigs = append(sigs, noteSignature{name: name, id: binary.BigEndian.Uint32(sig), sig: sig[4:]})
	}
	return text, sigs, nil
}

// openNote verifies a note against the given keys following
// c2sp.org/signed-note: signatures from unknown keys are ignored, a failing
// signature from a known key rejects the note, and at least one known key
// must have signed. It returns the text and the keys that verified.
func openNote(note []byte, keys []*Verifier) ([]byte, []*Verifier, error) {
	text, sigs, err := parseNote(note)
	if err != nil {
		return nil, nil, err
	}
	var verified []*Verifier
	for _, s := range sigs {
		for _, k := range keys {
			if k.name != s.name || k.id != s.id {
				continue
			}
			if err := k.verify(text, s.sig); err != nil {
				return nil, nil, fmt.Errorf("signature by %s: %w", k.name, err)
			}
			verified = append(verified, k)
		}
	}
	if len(verified) == 0 {
		return nil, nil, errors.New("no signature from a known key")
	}
	return text, verified, nil
}

// OpenNote verifies a signed note against Ed25519 note keys following
// c2sp.org/signed-note, and returns its text and the keys that signed it.
// Checkpoints and receipts have their own functions; OpenNote is for other
// notes, such as statements signed by the source of evidence.
func OpenNote(note []byte, keys []*Verifier) ([]byte, []*Verifier, error) {
	for _, k := range keys {
		if k.typ != SigEd25519 {
			return nil, nil, fmt.Errorf("key %s is not an Ed25519 note key", k.name)
		}
	}
	return openNote(note, keys)
}
