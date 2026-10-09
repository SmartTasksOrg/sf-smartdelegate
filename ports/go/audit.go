package smartdelegate

// Append-only, hash-chained decision log (JSON Lines).
//
// record.hash = sha256(prev_hash + canonical_json(record without "hash")).
// Editing, deleting or reordering any line breaks every hash after it.
// Truncating the tail is only detectable against a head hash kept elsewhere.

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// auditLines splits a log at "\n" and nowhere else: canonical JSON writes
// U+2028, U+2029 and U+0085 as themselves, and they are data, not line breaks.
func auditLines(text string) []string { return strings.Split(text, "\n") }

// decodeLossy reads bytes as UTF-8, with U+FFFD for what is not.
func decodeLossy(raw []byte) string {
	if utf8.Valid(raw) {
		return string(raw)
	}
	var b strings.Builder
	for len(raw) > 0 {
		r, size := utf8.DecodeRune(raw)
		b.WriteRune(r) // RuneError for an invalid byte
		raw = raw[size:]
	}
	return b.String()
}

// VerifyAudit recomputes the whole chain of the log at path. It returns the
// number of records and the head hash; the error (code audit_broken) names
// the first bad line.
func VerifyAudit(path string) (records int64, head string, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(*EngineError); ok {
				err = e
				return
			}
			err = newErr("internal", fmt.Sprint(r))
		}
	}()
	records, head = verifyAudit(path)
	return records, head, nil
}

func verifyAudit(path string) (int64, string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		throw("audit_io", "cannot read audit log: "+ioMessage(err))
	}
	if !utf8.Valid(raw) {
		throw("audit_broken", "the audit log is not UTF-8")
	}
	prev, n := genesis, int64(0)
	for i, line := range auditLines(string(raw)) {
		lineno := i + 1
		if strip(line) == "" {
			continue
		}
		parsed, perr := ParseJSON([]byte(line))
		rec, ok := parsed.(map[string]any)
		if perr != nil || !ok {
			throw("audit_broken", fmt.Sprintf("line %d: not JSON", lineno))
		}
		var claimed any = ""
		if h, has := rec["hash"]; has {
			claimed = h
			delete(rec, "hash")
		}
		if p, ok := rec["prev"].(string); !ok || p != prev {
			throw("audit_broken", fmt.Sprintf("line %d: prev hash does not match the line before", lineno))
		}
		if seq, has := rec["seq"]; !has || !pyEqual(seq, n+1) {
			throw("audit_broken", fmt.Sprintf("line %d: sequence number is not %d", lineno, n+1))
		}
		if c, ok := claimed.(string); !ok || sha256Hex([]byte(prev+Canon(rec))) != c {
			throw("audit_broken", fmt.Sprintf("line %d: content does not match its hash", lineno))
		}
		prev = claimed.(string)
		n++
	}
	return n, prev
}

func auditTail(path string, n int64) []any {
	out := []any{}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return out
	}
	if err != nil {
		throw("state_io", ioMessage(err))
	}
	var lines []string
	for _, l := range auditLines(decodeLossy(raw)) {
		if strip(l) != "" {
			lines = append(lines, l)
		}
	}
	if n <= 0 {
		return out
	}
	start := int64(len(lines)) - n
	if start < 0 {
		start = 0
	}
	for _, l := range lines[start:] {
		if v, err := ParseJSON([]byte(l)); err == nil {
			out = append(out, v)
		}
	}
	return out
}

type auditLog struct {
	path string
	seq  int64
	head string
	size int64
}

func newAuditLog(path string) *auditLog {
	a := &auditLog{path: path, head: genesis}
	if exists(path) {
		a.seq, a.head = verifyAudit(path)
	}
	if st, err := os.Stat(path); err == nil {
		a.size = st.Size()
	}
	return a
}

// resync chains onto the last record if another process appended. The engine
// holds the state-directory lock while this runs.
func (a *auditLog) resync() {
	var size int64
	if st, err := os.Stat(a.path); err == nil {
		size = st.Size()
	}
	if size == a.size {
		return
	}
	if size == 0 {
		throw("audit_broken", "the audit log was truncated while in use")
	}
	f, err := os.Open(a.path)
	if err != nil {
		throw("audit_io", "cannot read audit log: "+ioMessage(err))
	}
	defer f.Close()
	unreadable := newErr("audit_broken", "the last audit record is unreadable")
	// The last record is the last non-blank line of the final 1 MiB (the
	// reference's window). Read a small tail first: when it holds two or
	// more non-blank lines its last one is complete, and is the same line.
	var last string
	for window := int64(1 << 16); ; window *= 4 {
		start := size - window
		limit := size - (1 << 20)
		if limit < 0 {
			limit = 0
		}
		if start < limit {
			start = limit
		}
		raw := make([]byte, size-start)
		if _, err := f.ReadAt(raw, start); err != nil && err != io.EOF {
			throw("audit_io", "cannot read audit log: "+ioMessage(err))
		}
		found := 0
		for _, l := range auditLines(decodeLossy(raw)) {
			if strip(l) != "" {
				last = l
				found++
			}
		}
		if found >= 2 || start == limit {
			break
		}
	}
	parsed, perr := ParseJSON([]byte(last))
	rec, ok := parsed.(map[string]any)
	if perr != nil || !ok {
		panic(unreadable)
	}
	var seq int64
	switch s := rec["seq"].(type) {
	case int64:
		seq = s
	case bool:
		if s {
			seq = 1
		}
	case float64:
		if s != s || s > 9e18 || s < -9e18 {
			panic(unreadable)
		}
		seq = int64(s)
	case string:
		n, err := strconv.ParseInt(strip(s), 10, 64)
		if err != nil {
			panic(unreadable)
		}
		seq = n
	default:
		panic(unreadable)
	}
	hash, has := rec["hash"]
	if !has {
		panic(unreadable)
	}
	head, ok := hash.(string)
	if !ok {
		head = Canon(hash)
	}
	a.seq, a.head, a.size = seq, head, size
}

// append writes one record and returns its hash.
func (a *auditLog) append(record map[string]any, ts int64) string {
	a.resync()
	rec := make(map[string]any, len(record)+4)
	for k, v := range record {
		rec[k] = v
	}
	delete(rec, "hash")
	rec["seq"] = satAdd(a.seq, 1)
	rec["ts"] = ts
	rec["prev"] = a.head
	h := sha256Hex([]byte(a.head + Canon(rec)))
	rec["hash"] = h
	f, err := os.OpenFile(a.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		throw("audit_io", "cannot write audit log: "+ioMessage(err))
	}
	_, werr := f.WriteString(Canon(rec) + "\n")
	st, serr := f.Stat()
	cerr := f.Close()
	for _, err := range []error{werr, serr, cerr} {
		if err != nil {
			throw("audit_io", "cannot write audit log: "+ioMessage(err))
		}
	}
	a.size = st.Size()
	a.seq++
	a.head = h
	return h
}
