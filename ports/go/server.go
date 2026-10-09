package smartdelegate

// REST decision daemon. See spec/openapi.yaml.
//
// Two keys guard it:
//
//	pep key    enforcement points: /v1/authorize, /v1/filter, /v1/explain,
//	           /v1/obligations/apply, /v1/token/inspect, /v1/info
//	admin key  /v1/admin/* and issuing a root token without an OIDC ID token
//
// /v1/token needs no key for token exchange (holding the parent token is the
// authority) or for issuance backed by a verified OIDC ID token. TLS is not
// terminated here: bind to loopback or put it behind a mesh.

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// MaxBody is the largest request body the daemon reads.
const MaxBody = 8 * 1024 * 1024

type route struct{ op, need string }

var routes = map[string]route{
	"GET /v1/info":               {"info", "pep"},
	"POST /v1/authorize":         {"authorize", "pep"},
	"POST /v1/filter":            {"filter", "pep"},
	"POST /v1/explain":           {"explain", "pep"},
	"POST /v1/obligations/apply": {"apply_obligations", "pep"},
	"POST /v1/token/inspect":     {"inspect_token", "pep"},
	"POST /v1/admin/revoke":      {"revoke", "admin"},
	"POST /v1/admin/approve":     {"approve", "admin"},
	"POST /v1/admin/reload":      {"reload", "admin"},
	"GET /v1/admin/approvals":    {"approvals", "admin"},
	"GET /v1/admin/audit/verify": {"audit_verify", "admin"},
	"GET /v1/admin/audit/tail":   {"audit_tail", "admin"},
}

func sameKey(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

type handler struct {
	engine           Caller
	adminKey, pepKey string
}

// NewHandler is the daemon's HTTP handler for an engine. Both keys must be
// set by the caller; Serve checks their length.
func NewHandler(engine Caller, adminKey, pepKey string) http.Handler {
	return &handler{engine: engine, adminKey: adminKey, pepKey: pepKey}
}

func sendJSON(w http.ResponseWriter, status int, body any) {
	raw := MarshalJSON(body)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func httpError(code, message string) map[string]any {
	return map[string]any{"ok": false, "error": map[string]any{"code": code, "message": message}}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "smartdelegate")
	method := r.Method
	if method != "GET" && method != "POST" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = fmt.Fprintf(w, "Unsupported method (%q)\n", method)
		return
	}
	path, query, _ := strings.Cut(r.RequestURI, "?")
	if strings.HasPrefix(r.RequestURI, "//") {
		// the reference's HTTP server collapses leading slashes of the request target
		path, query, _ = strings.Cut("/"+strings.TrimLeft(r.RequestURI, "/"), "?")
	}
	if path == "/healthz" {
		sendJSON(w, 200, map[string]any{"ok": true})
		return
	}
	var body any = map[string]any{}
	if method == "POST" {
		problem := ""
		var raw []byte
		switch n := r.ContentLength; {
		case n > MaxBody:
			// Refuse without parsing. A bounded part of the body is read and
			// thrown away first, so a client that is still sending can read
			// the answer instead of a connection reset.
			_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.CopyN(io.Discard, r.Body, 4*MaxBody)
			w.Header().Set("Connection", "close")
			problem = "request body is too large"
		case n > 0:
			raw = make([]byte, n)
			if _, err := io.ReadFull(r.Body, raw); err != nil {
				problem = "body is not JSON"
			}
		}
		if problem == "" && len(bytes.Trim(raw, " \t\n\r\v\f")) > 0 {
			v, err := parseJSONBytes(raw)
			if err != nil {
				problem = "body is not JSON"
			}
			body = v
		}
		if problem != "" {
			sendJSON(w, 400, httpError("invalid_input", problem))
			return
		}
	}
	key := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		key = strip(auth[7:])
	}
	isAdmin := sameKey(key, h.adminKey)
	isPep := sameKey(key, h.pepKey) || isAdmin
	var op string
	var allowed bool
	bodyMap, isMap := body.(map[string]any)
	if rt, known := routes[method+" "+path]; method == "POST" && path == "/v1/token" {
		_, hasSubject := bodyMap["subject_token"]
		_, hasIDToken := bodyMap["id_token"]
		switch {
		case isMap && hasSubject:
			op, allowed = "exchange_token", true
		case isMap && hasIDToken:
			// identity comes from the ID token alone
			stripped := make(map[string]any, len(bodyMap))
			for k, v := range bodyMap {
				if k != "user" {
					stripped[k] = v
				}
			}
			body = stripped
			op, allowed = "issue_token", true
		default:
			op, allowed = "issue_token", isAdmin
		}
	} else if known {
		op = rt.op
		allowed = isAdmin
		if rt.need == "pep" {
			allowed = isPep
		}
		if op == "audit_tail" {
			n := int64(20)
			for _, kv := range strings.Split(query, "&") {
				if strings.HasPrefix(kv, "n=") {
					if v := kv[2:]; allDigits(v) {
						value, _ := decimal(v)
						n = clamp(value)
					}
					break
				}
			}
			body = map[string]any{"n": n}
		}
	} else {
		sendJSON(w, 404, httpError("not_found", "no such endpoint"))
		return
	}
	if !allowed {
		sendJSON(w, 401, httpError("unauthorized", "missing or wrong API key"))
		return
	}
	result := h.engine.Call(op, body)
	status := 400
	if result["ok"] == true {
		status = 200
	}
	sendJSON(w, status, result)
}

// ListenAddress splits "host:port"; an empty host is 127.0.0.1.
func ListenAddress(text string) (string, error) {
	i := strings.LastIndex(text, ":")
	host, port := "", text
	if i >= 0 {
		host, port = text[:i], text[i+1:]
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return "", fmt.Errorf("listen address %q: the port must be a number", text)
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), port), nil
}

// Server is a running daemon.
type Server struct {
	// URL is "http://host:port" of the bound address.
	URL      string
	listener net.Listener
	http     *http.Server
}

// Listen binds the daemon. Both keys must be 16 characters or longer.
func Listen(engine Caller, listen, adminKey, pepKey string) (*Server, error) {
	if len(adminKey) < 16 || len(pepKey) < 16 {
		return nil, errors.New("serve needs admin_key and pep_key (16+ characters) in the config or SMARTDELEGATE_ADMIN_KEY / SMARTDELEGATE_PEP_KEY")
	}
	addr, err := ListenAddress(listen)
	if err != nil {
		return nil, err
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	tcp := l.Addr().(*net.TCPAddr)
	return &Server{URL: fmt.Sprintf("http://%s:%d", tcp.IP.String(), tcp.Port), listener: l,
		http: &http.Server{Handler: NewHandler(engine, adminKey, pepKey), MaxHeaderBytes: 1 << 20}}, nil
}

// Serve answers requests until Close is called.
func (s *Server) Serve() error {
	err := s.http.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close stops the daemon.
func (s *Server) Close() error { return s.http.Close() }
