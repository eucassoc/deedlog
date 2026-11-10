//go:build js && wasm

// Command wasm exposes receipt verification to the verification page as
// window.deedlog. Every function takes and returns strings; results are
// JSON objects with "ok" and either the result or "error".
package main

import (
	"encoding/json"
	"strings"
	"syscall/js"

	"github.com/eucassoc/deedlog/core"
	"github.com/eucassoc/deedlog/verifier"
)

func main() {
	api := js.Global().Get("Object").New()
	api.Set("open", js.FuncOf(func(_ js.Value, args []js.Value) any {
		_, rc, err := load(args)
		if err != nil {
			return fail(err)
		}
		return ok(map[string]any{"origin": rc.Receipt.Origin, "index": rc.Receipt.Index,
			"operator": rc.Operator.Name, "url": rc.Operator.URL})
	}))
	api.Set("checkpointSize", js.FuncOf(func(_ js.Value, args []js.Value) any {
		reg, rc, err := load(args)
		if err != nil {
			return fail(err)
		}
		c, err := reg.VerifyCheckpoint(rc, []byte(args[2].String()))
		if err != nil {
			return fail(err)
		}
		return ok(map[string]any{"size": c.Size})
	}))
	api.Set("check", js.FuncOf(func(_ js.Value, args []js.Value) any {
		reg, rc, err := load(args)
		if err != nil {
			return fail(err)
		}
		res, err := reg.Check(rc, []byte(args[2].String()), args[3].String())
		if err != nil {
			return fail(err)
		}
		return ok(map[string]any{"result": res})
	}))
	js.Global().Set("deedlog", api)
	if ready := js.Global().Get("deedlogReady"); ready.Type() == js.TypeFunction {
		ready.Invoke()
	}
	select {}
}

// load parses the registry (args[0]) and opens the receipt (args[1]), which
// may be a receipt URL, its fragment, or the signed receipt note itself.
func load(args []js.Value) (*verifier.Registry, *verifier.Receipt, error) {
	reg, err := verifier.ParseRegistry([]byte(args[0].String()))
	if err != nil {
		return nil, nil, err
	}
	input := strings.TrimSpace(args[1].String())
	note := []byte(input + "\n")
	if !strings.HasPrefix(input, core.ReceiptHeader) {
		if note, err = core.ReceiptFromURL(input); err != nil {
			return nil, nil, err
		}
	}
	rc, err := reg.OpenReceipt(note)
	return reg, rc, err
}

func ok(fields map[string]any) string {
	fields["ok"] = true
	b, _ := json.Marshal(fields)
	return string(b)
}

func fail(err error) string {
	b, _ := json.Marshal(map[string]any{"ok": false, "error": err.Error()})
	return string(b)
}
