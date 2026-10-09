package smartdelegate

// Applying a field mask and a row filter to JSON data.
//
// Field paths are relative to the resource: `email`, `address.zip`,
// `orders[].total`. `[]` stands for "each element of this array".
//
// Rules (fail closed):
//   - a denied path is dropped, or replaced by "[REDACTED]" when the catalog
//     says `mask: redact`; its whole subtree goes with it
//   - an allowed path is kept; children that have their own catalog entry are
//     still checked one by one, other children are kept with the parent
//   - a path the catalog does not list, under no allowed parent, is dropped

import (
	"sort"
	"strings"
)

const (
	redacted    = "[REDACTED]"
	fieldAllow  = "allow"
	fieldDeny   = "deny"
	fieldRedact = "redact"
)

type fieldMask struct {
	status map[string]string
}

func (m *fieldMask) hasChildren(path string) bool {
	a, b := path+".", path+"[]"
	for k := range m.status {
		if strings.HasPrefix(k, a) || strings.HasPrefix(k, b) {
			return true
		}
	}
	return false
}

func isContainer(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}

func (m *fieldMask) walkValue(v any, path string, inherit bool, masked map[string]bool) (bool, any) {
	switch x := v.(type) {
	case map[string]any:
		return true, m.walkObject(x, path, inherit, masked)
	case []any:
		p := path + "[]"
		st := m.status[p]
		out := []any{}
		for _, el := range x {
			switch {
			case st == fieldDeny:
				masked[p] = true
			case st == fieldRedact:
				masked[p] = true
				out = append(out, redacted)
			case st == fieldAllow:
				if keep, y := m.walkValue(el, p, true, masked); keep {
					out = append(out, y)
				}
			case isContainer(el):
				if keep, y := m.walkValue(el, p, inherit, masked); keep {
					out = append(out, y)
				}
			case inherit:
				out = append(out, el)
			default:
				masked[p] = true
			}
		}
		return true, out
	}
	if inherit {
		return true, v
	}
	return false, nil
}

func (m *fieldMask) walkObject(obj map[string]any, prefix string, inherit bool, masked map[string]bool) map[string]any {
	out := map[string]any{}
	for k, v := range obj {
		p := k
		if prefix != "" {
			p = prefix + "." + k
		}
		st := m.status[p]
		switch {
		case st == fieldDeny:
			masked[p] = true
		case st == fieldRedact:
			masked[p] = true
			out[k] = redacted
		case st == fieldAllow:
			if m.hasChildren(p) {
				if keep, x := m.walkValue(v, p, true, masked); keep {
					out[k] = x
				}
			} else {
				out[k] = v
			}
		case inherit && !m.hasChildren(p):
			out[k] = v
		case isContainer(v) && m.hasChildren(p):
			if keep, x := m.walkValue(v, p, inherit, masked); keep {
				out[k] = x
			}
		case inherit:
			out[k] = v
		default:
			masked[p] = true
		}
	}
	return out
}

// sameJSON is JSON equality for a row filter: true is not 1, 1 is not 1.0.
func sameJSON(a, b any) bool {
	return jsonKind(a) == jsonKind(b) && pyEqual(a, b)
}

func rowMatches(row map[string]any, rowFilter []map[string]any) bool {
	for _, c := range rowFilter {
		col, ok := c["column"].(string)
		if !ok {
			if isContainer(c["column"]) {
				panic("row filter column is not a name")
			}
			return false
		}
		v, has := row[col]
		if !has || !sameJSON(v, c["value"]) {
			return false
		}
	}
	return true
}

// applyMask filters data, which is one record or a list of records. It
// returns the data, the masked paths (sorted) and the number of rows dropped.
func applyMask(data any, mask *fieldMask, rowFilter []map[string]any) (any, []string, int64) {
	masked := map[string]bool{}
	var out any
	var dropped int64
	switch x := data.(type) {
	case []any:
		rows := []any{}
		for _, r := range x {
			if rec, ok := r.(map[string]any); ok && rowMatches(rec, rowFilter) {
				rows = append(rows, mask.walkObject(rec, "", false, masked))
			} else {
				dropped++
			}
		}
		out = rows
	case map[string]any:
		if rowMatches(x, rowFilter) {
			out = mask.walkObject(x, "", false, masked)
		} else {
			dropped = 1
		}
	default:
		// a bare scalar has no field identity, so nothing can authorise it
		dropped = 1
	}
	paths := make([]string, 0, len(masked))
	for p := range masked {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return out, paths, dropped
}
