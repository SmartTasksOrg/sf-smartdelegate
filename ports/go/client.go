package smartdelegate

// Thin REST client for the daemon (`smartdelegate serve` of any port).

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"
)

type clientRoute struct{ method, path, key string }

var clientRoutes = map[string]clientRoute{
	"authorize":         {"POST", "/v1/authorize", "pep"},
	"filter":            {"POST", "/v1/filter", "pep"},
	"explain":           {"POST", "/v1/explain", "pep"},
	"apply_obligations": {"POST", "/v1/obligations/apply", "pep"},
	"inspect_token":     {"POST", "/v1/token/inspect", "pep"},
	"info":              {"GET", "/v1/info", "pep"},
	"exchange_token":    {"POST", "/v1/token", ""},
	"issue_token":       {"POST", "/v1/token", "admin"},
	"revoke":            {"POST", "/v1/admin/revoke", "admin"},
	"approve":           {"POST", "/v1/admin/approve", "admin"},
	"reload":            {"POST", "/v1/admin/reload", "admin"},
	"approvals":         {"GET", "/v1/admin/approvals", "admin"},
	"audit_verify":      {"GET", "/v1/admin/audit/verify", "admin"},
	"audit_tail":        {"GET", "/v1/admin/audit/tail", "admin"},
}

// Client calls a running daemon. It has the same Call as an Engine.
type Client struct {
	url      string
	pepKey   string
	adminKey string
	// HTTP is the client used for requests. It never goes through an
	// environment proxy: decision traffic is not routed by HTTP_PROXY.
	HTTP *http.Client
}

// NewClient makes a client for the daemon at url. Either key may be empty;
// the admin key also serves where the pep key is asked for.
func NewClient(url, pepKey, adminKey string) *Client {
	if pepKey == "" {
		pepKey = adminKey
	}
	return &Client{url: strings.TrimRight(url, "/"), pepKey: pepKey, adminKey: adminKey,
		HTTP: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 4}}}
}

func clientError(code, message string) map[string]any {
	return map[string]any{"ok": false, "error": map[string]any{"code": code, "message": message}}
}

// Call runs one operation over REST. Like Engine.Call it never panics and
// always returns a result; a daemon that cannot be reached or answers with
// something that is not a JSON object is an error result (code
// daemon_unreachable or http_error), never an allow.
func (c *Client) Call(op string, payload any) (result map[string]any) {
	defer func() {
		if r := recover(); r != nil {
			result = clientError("internal", asEngineError(r).Message)
		}
	}()
	rt, ok := clientRoutes[op]
	if !ok {
		return clientError("unknown_op", "no operation named '"+op+"'")
	}
	input, err := normalize(payload, 0)
	if err != nil {
		return clientError("invalid_input", "the request body is not JSON: "+err.Error())
	}
	in, _ := input.(map[string]any)
	path := rt.path
	if n, has := in["n"]; op == "audit_tail" && has {
		if !isInt(n) {
			return clientError("invalid_input", "'n' must be an integer")
		}
		path += "?n=" + Canon(n)
	}
	key := ""
	switch rt.key {
	case "pep":
		key = c.pepKey
	case "admin":
		key = c.adminKey
	}
	if op == "issue_token" && truthy(in["id_token"]) {
		key = "" // the ID token is the credential
	}
	var body io.Reader
	if rt.method == "POST" {
		body = bytes.NewReader(MarshalJSON(input))
	}
	req, err := http.NewRequest(rt.method, c.url+path, body)
	if err != nil {
		return clientError("daemon_unreachable", err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		// an unreachable decision point is never an allow
		return clientError("daemon_unreachable", err.Error())
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return clientError("daemon_unreachable", err.Error())
	}
	parsed, perr := parseJSONBytes(raw)
	out, isMap := parsed.(map[string]any)
	if perr != nil || !isMap {
		return clientError("http_error", "HTTP "+resp.Status+": the answer is not a JSON object")
	}
	if resp.StatusCode >= 400 && out["ok"] == true {
		// an error status never carries a success
		return clientError("http_error", "HTTP "+resp.Status)
	}
	return out
}
