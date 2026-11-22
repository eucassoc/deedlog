package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"
)

// Field is one key and value of an event's description.
type Field struct {
	Key, Value string
}

// Event is something that happened, recorded as its own description: the
// names and identifiers in Meta, never the data the event is about.
type Event struct {
	Source Source
	Name   string  // recorded as the meta key "event"
	Meta   []Field // in the order they are to be written
	At     time.Time
}

// EventRecord returns the next record of a chain for an event: its record
// bytes, and the body its subject digest is of. s is the summary of the
// chain so far, or the zero Summary to start the chain named chain.
//
// The body is the JSON object of the event name, the fields and the time;
// the record repeats the fields in meta. Both are written exactly as the
// JavaScript implementation writes them (makeRecord in js/deedlog.js), so
// that the two produce the same bytes from the same input: fields with an
// empty value or the key "event" are left out, a repeated key keeps its
// first place and its last value, and keys that are array indices come
// first, in numeric order, as they do in a JavaScript object.
func EventRecord(s Summary, chain string, e Event) (line, body []byte, err error) {
	if s.Count > 0 {
		if !validDigest(s.Head) {
			return nil, nil, errors.New("summary does not describe a verified chain")
		}
		chain = s.Chain
	}
	if chain == "" {
		return nil, nil, errors.New("chain ID must not be empty")
	}
	if e.Name == "" {
		return nil, nil, errors.New("event name must not be empty")
	}
	var given []Field
	for _, f := range e.Meta {
		if i := slices.IndexFunc(given, func(g Field) bool { return g.Key == f.Key }); i >= 0 {
			given[i].Value = f.Value
		} else {
			given = append(given, f)
		}
	}
	fields := []Field{{"event", e.Name}}
	for _, f := range given {
		if f.Value != "" && f.Key != "event" {
			fields = append(fields, f)
		}
	}
	slices.SortStableFunc(fields, func(a, b Field) int {
		ai, aok := arrayIndex(a.Key)
		bi, bok := arrayIndex(b.Key)
		switch {
		case aok && bok:
			return int(int64(ai) - int64(bi))
		case aok:
			return -1
		case bok:
			return 1
		}
		return 0
	})
	for _, v := range append([]string{chain, e.Source.Type, e.Source.ID, e.Source.Collector}, flatten(fields)...) {
		if !utf8.ValidString(v) {
			return nil, nil, fmt.Errorf("%q is not valid UTF-8", v)
		}
	}
	at := e.At.UTC().Format("2006-01-02T15:04:05Z")

	about := slices.Clone(fields)
	if i := slices.IndexFunc(about, func(g Field) bool { return g.Key == "at" }); i >= 0 {
		about[i].Value = at
	} else {
		about = append(about, Field{"at", at})
	}
	var b bytes.Buffer
	writeObject(&b, about)
	body = bytes.Clone(b.Bytes())
	sum := sha256.Sum256(body)

	b.Reset()
	b.WriteString(`{"spec":`)
	writeString(&b, SpecVersion)
	b.WriteString(`,"chain":`)
	writeString(&b, chain)
	b.WriteString(`,"seq":` + strconv.FormatUint(s.Count, 10))
	if s.Count > 0 {
		b.WriteString(`,"prev":`)
		writeString(&b, s.Head)
	}
	b.WriteString(`,"collected_at":"` + at + `","source":`)
	writeObject(&b, []Field{{"type", e.Source.Type}, {"id", e.Source.ID}, {"collector", e.Source.Collector}})
	b.WriteString(`,"subject":{"media_type":"application/json","size":` + strconv.Itoa(len(body)) +
		`,"digest":{"sha256":"` + hex.EncodeToString(sum[:]) + `"}},"meta":`)
	writeObject(&b, fields)
	b.WriteString("}")
	return b.Bytes(), body, nil
}

// Next returns the summary of the chain after line is appended to the chain
// that s describes. It does not verify line.
func (s Summary) Next(chain string, line []byte) Summary {
	if s.Count == 0 {
		s.Chain = chain
	}
	s.Count++
	s.Head = Digest(line)
	s.Root = ""
	return s
}

func flatten(fields []Field) []string {
	var out []string
	for _, f := range fields {
		out = append(out, f.Key, f.Value)
	}
	return out
}

// arrayIndex reports whether a key is an array index in JavaScript, which
// orders such keys before the others: the canonical decimal form of an
// integer below 2^32 - 1.
func arrayIndex(key string) (uint32, bool) {
	n, err := strconv.ParseUint(key, 10, 32)
	if err != nil || n == 1<<32-1 || strconv.FormatUint(n, 10) != key {
		return 0, false
	}
	return uint32(n), true
}

func writeObject(b *bytes.Buffer, fields []Field) {
	b.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		writeString(b, f.Key)
		b.WriteByte(':')
		writeString(b, f.Value)
	}
	b.WriteByte('}')
}

// writeString writes s as JSON.stringify does: only the quote, the
// backslash and control characters are escaped.
func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == '\b':
			b.WriteString(`\b`)
		case c == '\f':
			b.WriteString(`\f`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20:
			fmt.Fprintf(b, `\u%04x`, c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
}
