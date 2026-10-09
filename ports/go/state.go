package smartdelegate

// Mutable engine state: revocations, approvals, spend ledger.
//
// One JSON file in the state directory. The engine holds the state-directory
// lock for every operation and re-reads the file at the start of each one, so
// processes sharing a directory see each other's changes on the next call.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"unicode/utf8"
)

// A key missing from the file is an empty object: older engines and other
// ports sharing the directory may not write `revoked_users`.
var stateKeys = []string{"revoked", "approvals", "pending", "ledger", "limits", "revoked_users"}

type state struct {
	path string // "" for an in-memory engine
	raw  string
	data map[string]any
}

func newState(dir string) (*state, *EngineError) {
	s := &state{data: map[string]any{}}
	for _, k := range stateKeys {
		s.data[k] = map[string]any{}
	}
	if dir != "" {
		s.path = filepath.Join(dir, "state.json")
	}
	return s, s.refresh()
}

func (s *state) refresh() *EngineError {
	if s.path == "" {
		return nil
	}
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return newErr("state_io", ioMessage(err))
	}
	text := string(raw)
	if text == s.raw {
		return nil
	}
	// an unreadable state file must not silently drop revocations
	corrupt := newErr("state_io", "state.json is corrupt")
	if !utf8.Valid(raw) {
		return corrupt
	}
	parsed, perr := ParseJSON(raw)
	data, ok := parsed.(map[string]any)
	if perr != nil || !ok {
		return corrupt
	}
	for _, k := range stateKeys {
		if _, has := data[k]; !has {
			data[k] = map[string]any{}
		}
		if _, ok := data[k].(map[string]any); !ok {
			return corrupt
		}
	}
	s.data, s.raw = data, text
	return nil
}

func (s *state) save() {
	if s.path == "" {
		return
	}
	text := Canon(s.data)
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o644); err != nil {
		throw("state_io", ioMessage(err))
	}
	if err := os.Rename(tmp, s.path); err != nil {
		throw("state_io", ioMessage(err))
	}
	s.raw = text
}

func (s *state) section(name string) map[string]any {
	return s.data[name].(map[string]any)
}

// num reads an integer the state file is expected to hold. Anything else is
// a corrupt state file, and the operation fails (as `internal`).
func num(v any) int64 {
	n, ok := v.(int64)
	if !ok {
		panic("state.json holds a value that is not a 64-bit integer")
	}
	return n
}

func (s *state) prune(now int64) {
	keep := func(name string, alive func(v any) bool) {
		out := map[string]any{}
		for k, v := range s.section(name) {
			if alive(v) {
				out[k] = v
			}
		}
		s.data[name] = out
	}
	keep("revoked", func(v any) bool { return satAdd(num(v), 86400) > now })
	keep("approvals", func(v any) bool { return num(v.(map[string]any)["exp"]) > now })
	keep("pending", func(v any) bool { return satAdd(num(v.(map[string]any)["requested_at"]), 86400) > now })
}
