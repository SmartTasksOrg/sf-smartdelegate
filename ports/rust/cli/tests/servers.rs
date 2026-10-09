//! The daemon and the HTTP proxy as processes, against an upstream this test
//! starts: hard responses (binary, oversized, not JSON), slow upstream calls,
//! the concurrency cap, and latency of token issuance (TCP_NODELAY).
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_smartdelegate");
const MIB: usize = 1024 * 1024;
const SLOW: Duration = Duration::from_millis(1500);

fn bundle() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec/conformance/bundle")
}

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Tmp {
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!("smartdelegate-servers-{}-{}-{}", std::process::id(), tag, N.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Tmp(d)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A started `smartdelegate serve` or `http-proxy`, killed on drop.
struct Proc {
    child: Child,
    addr: String,
}

impl Proc {
    fn start(args: &[&str]) -> Proc {
        let mut child = Command::new(BIN).args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let mut line = String::new();
        BufReader::new(child.stderr.take().unwrap()).read_line(&mut line).unwrap();
        let addr = line.trim().rsplit("http://").next().unwrap_or("").to_string();
        assert!(line.contains("listening on") && !addr.is_empty(), "did not start: {line}");
        Proc { child, addr }
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---- the upstream -----------------------------------------------------------

fn pdf() -> Vec<u8> {
    // not UTF-8, with NULs, CR LF and every byte value
    let mut b = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\r\n\x00\x00\xff\xfe".to_vec();
    b.extend((0..=255u8).cycle().take(70_000));
    b
}

fn big(len: usize) -> Vec<u8> {
    (0..len).map(|i| b'a' + (i % 26) as u8).collect()
}

struct Upstream {
    addr: String,
    /// requests being served right now / the most there ever were at once
    in_flight: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    hits: Arc<AtomicUsize>,
    /// the request target of the last request received
    last_target: Arc<std::sync::Mutex<String>>,
}

fn upstream() -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (in_flight, peak, hits) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let last_target = Arc::new(std::sync::Mutex::new(String::new()));
    let (f, p, h, lt) = (in_flight.clone(), peak.clone(), hits.clone(), last_target.clone());
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut s) = conn else { continue };
            let (f, p, h, lt) = (f.clone(), p.clone(), h.clone(), lt.clone());
            std::thread::spawn(move || {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut first = String::new();
                if r.read_line(&mut first).is_err() {
                    return;
                }
                loop {
                    let mut l = String::new();
                    if r.read_line(&mut l).unwrap_or(0) == 0 || l == "\r\n" {
                        break;
                    }
                }
                let target = first.split(' ').nth(1).unwrap_or("").to_string();
                *lt.lock().unwrap() = target.clone();
                let path = target.split('?').next().unwrap_or("").to_string();
                h.fetch_add(1, Ordering::SeqCst);
                let now = f.fetch_add(1, Ordering::SeqCst) + 1;
                p.fetch_max(now, Ordering::SeqCst);
                let customer = br#"{"id":"c-1","email":"ada@example.com","ssn":"123-45-6789","region":"EU"}"#.to_vec();
                let (ctype, body): (&str, Vec<u8>) = match path.as_str() {
                    "/customers/slow" => {
                        std::thread::sleep(SLOW);
                        ("application/json", customer)
                    }
                    "/customers/pdf" | "/files/pdf" => ("application/pdf", pdf()),
                    "/files/exact" => ("application/octet-stream", big(32 * MIB)),
                    "/files/over" => ("application/octet-stream", big(32 * MIB + 1)),
                    "/files/huge" | "/customers/huge" => ("application/json", big(40 * MIB)),
                    "/files/untyped" => ("", b"\x00\x01".to_vec()),
                    _ => ("application/json", customer),
                };
                let ct = if ctype.is_empty() { String::new() } else { format!("Content-Type: {ctype}\r\n") };
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\n{ct}Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes());
                let _ = s.write_all(&body);
                f.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Upstream { addr, in_flight, peak, hits, last_target }
}

// ---- a small HTTP client (one request per connection) ------------------------

struct Reply {
    status: u16,
    headers: String,
    body: Vec<u8>,
    took: Duration,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|_| panic!("not JSON: {}", String::from_utf8_lossy(&self.body[..self.body.len().min(200)])))
    }
    fn header(&self, name: &str) -> Option<String> {
        self.headers.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string()))
    }
}

fn request(addr: &str, method: &str, path: &str, bearer: &str, body: Option<&Value>) -> Reply {
    let started = Instant::now();
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_nodelay(true).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    let payload = body.map(|b| b.to_string()).unwrap_or_default();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {bearer}\r\nConnection: close\r\n");
    if body.is_some() {
        head += &format!("Content-Type: application/json\r\nContent-Length: {}\r\n", payload.len());
    }
    s.write_all(format!("{head}\r\n{payload}").as_bytes()).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or_else(|| panic!("no response head in {} bytes", raw.len()));
    let headers = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = headers.split(' ').nth(1).and_then(|x| x.parse().ok()).unwrap();
    let mut body = raw[split + 4..].to_vec();
    if headers.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        body = dechunk(&body);
    }
    Reply { status, headers, body, took: started.elapsed() }
}

fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(eol) = b.windows(2).position(|w| w == b"\r\n") else { break };
        let n = usize::from_str_radix(String::from_utf8_lossy(&b[..eol]).split(';').next().unwrap().trim(), 16).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&b[eol + 2..eol + 2 + n]);
        b = &b[eol + 2 + n + 2..];
    }
    out
}

// ---- the stack ----------------------------------------------------------------

struct Stack {
    _tmp: Tmp,
    up: Upstream,
    proxy: Proc,
    token: String,
}

fn stack(tag: &str, proxy_args: &[&str]) -> Stack {
    let tmp = Tmp::new(tag);
    let up = upstream();
    let state = tmp.0.join("state");
    let routes = tmp.0.join("routes.json");
    let read = |path: &str, extra: Value| {
        let mut r = json!({"upstream": "crm", "method": "GET", "path": path, "action": "read", "resource": "crm.customer", "id": "{id}"});
        for (k, v) in extra.as_object().unwrap() {
            r[k] = v.clone();
        }
        r
    };
    std::fs::write(
        &routes,
        json!({
            "upstreams": {"crm": {"base_url": format!("http://{}", up.addr)}},
            "routes": [read("/customers/{id}", json!({})), read("/files/{id}", json!({"response": "passthrough"}))],
        })
        .to_string(),
    )
    .unwrap();
    let common = ["--bundle".to_string(), bundle().to_string_lossy().to_string(), "--state".to_string(), state.to_string_lossy().to_string()];
    let out = Command::new(BIN).args(["token", "issue", "--user", "alice", "--agent", "support-bot", "--role", "support-agent", "--raw"]).args(&common).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let token = String::from_utf8(out.stdout).unwrap().trim().to_string();
    let mut args: Vec<&str> = vec!["http-proxy", "--routes", routes.to_str().unwrap(), "--listen", "127.0.0.1:0"];
    args.extend(common.iter().map(|s| s.as_str()));
    args.extend_from_slice(proxy_args);
    let proxy = Proc::start(&args);
    Stack { _tmp: tmp, up, proxy, token }
}

impl Stack {
    fn get(&self, path: &str) -> Reply {
        request(&self.proxy.addr, "GET", path, &self.token, None)
    }
}

// ---- hard responses (live findings L-4, L-5) ---------------------------------

#[test]
fn a_passthrough_route_hands_on_the_upstreams_bytes_untouched() {
    let s = stack("pdf", &[]);
    let r = s.get("/crm/files/pdf");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body[..r.body.len().min(300)]));
    assert_eq!(r.header("Content-Type").as_deref(), Some("application/pdf"));
    assert!(r.body == pdf(), "the bytes differ: {} received, {} sent", r.body.len(), pdf().len());
    // an upstream that names no content type
    let r = s.get("/crm/files/untyped");
    assert_eq!((r.status, r.header("Content-Type").as_deref(), r.body.as_slice()), (200, Some("application/octet-stream"), &b"\x00\x01"[..]));
    // the decision still comes first: no token, no bytes
    let r = request(&s.proxy.addr, "GET", "/crm/files/pdf", "not-a-token", None);
    assert_eq!((r.status, r.json()["error"]["code"].as_str()), (403, Some("token_invalid")));

    // a route that filters still withholds what it cannot field-check
    let before = s.up.hits.load(Ordering::SeqCst);
    let r = s.get("/crm/customers/pdf");
    assert_eq!((r.status, r.json()["error"]["code"].as_str()), (502, Some("unfilterable_response")), "{}", r.headers);
    assert!(!r.body.windows(4).any(|w| w == b"%PDF"), "nothing of the upstream body is in the refusal");
    assert_eq!(s.up.hits.load(Ordering::SeqCst), before + 1);
    // and filters what it can
    let r = s.get("/crm/customers/c-1");
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), json!({"id": "c-1", "email": "ada@example.com", "region": "EU"}));
}

#[test]
fn a_passthrough_response_over_32_mb_is_refused_not_cut() {
    let s = stack("big", &[]);
    // exactly the limit is delivered whole
    let r = s.get("/crm/files/exact");
    assert_eq!(r.status, 200);
    assert_eq!(r.body.len(), 32 * MIB);
    assert!(r.body == big(32 * MIB), "the body was altered");
    // one byte more is refused: never a 200 with part of the body
    for path in ["/crm/files/over", "/crm/files/huge", "/crm/customers/huge"] {
        let r = s.get(path);
        assert_eq!(r.status, 502, "{path}: {} bytes came back", r.body.len());
        assert!(r.body.len() < 1000, "{path}: {} bytes came back", r.body.len());
        let e = r.json();
        assert_eq!((e["error"]["code"].as_str(), e["error"]["by"].as_str()), (Some("unfilterable_response"), Some("smartdelegate")), "{path}");
    }
    // the proxy is still in good health afterwards
    assert_eq!(s.get("/crm/customers/c-1").status, 200);
}

// ---- slow upstream calls (live finding L-6) ------------------------------------

/// `n` requests on threads of their own; returns when the upstream is serving all of them.
fn start_slow(s: &Stack, n: usize) -> Vec<std::thread::JoinHandle<Reply>> {
    let handles: Vec<_> = (0..n)
        .map(|_| {
            let (addr, token) = (s.proxy.addr.clone(), s.token.clone());
            std::thread::spawn(move || request(&addr, "GET", "/crm/customers/slow", &token, None))
        })
        .collect();
    let deadline = Instant::now() + Duration::from_secs(10);
    while s.up.in_flight.load(Ordering::SeqCst) < n {
        assert!(Instant::now() < deadline, "only {} of {n} slow calls reached the upstream", s.up.in_flight.load(Ordering::SeqCst));
        std::thread::sleep(Duration::from_millis(5));
    }
    handles
}

#[test]
fn slow_upstream_calls_do_not_hold_up_the_other_agents() {
    let s = stack("slow", &[]);
    assert_eq!(s.get("/crm/customers/c-1").status, 200); // warm up
    let n = 40; // ten times the old pool of 4 threads
    let slow = start_slow(&s, n);
    // while all of them wait on the upstream, ordinary calls are answered at once
    let mut worst = Duration::ZERO;
    for _ in 0..20 {
        let r = s.get("/crm/customers/c-1");
        assert_eq!(r.status, 200);
        worst = worst.max(r.took);
    }
    assert_eq!(s.up.in_flight.load(Ordering::SeqCst), n, "the slow calls were still in flight while the fast ones ran");
    println!("worst fast call with {n} slow upstream calls in flight: {worst:?} (a slow call takes {SLOW:?})");
    assert!(worst < Duration::from_millis(300), "a fast call took {worst:?} behind {n} slow ones");
    for h in slow {
        let r = h.join().unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.json()["id"], json!("c-1"));
        assert!(r.took < SLOW + Duration::from_millis(1500), "a slow call took {:?}: they did not run side by side", r.took);
    }
    assert!(s.up.peak.load(Ordering::SeqCst) >= n);
}

#[test]
fn the_concurrency_cap_refuses_instead_of_queueing_or_exhausting() {
    let cap = 6;
    let s = stack("cap", &["--max-concurrent", "6"]);
    assert_eq!(s.get("/crm/customers/c-1").status, 200);
    let slow = start_slow(&s, cap);
    // every slot is taken: further requests are refused at once, and none
    // of them reaches the upstream
    let hits = s.up.hits.load(Ordering::SeqCst);
    for _ in 0..30 {
        let r = s.get("/crm/customers/c-1");
        assert_eq!(r.status, 503, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.header("Retry-After").as_deref(), Some("1"));
        let e = r.json();
        assert_eq!((e["error"]["code"].as_str(), e["error"]["by"].as_str()), (Some("overloaded"), Some("smartdelegate")));
        assert!(r.took < Duration::from_millis(300), "the refusal took {:?}", r.took);
    }
    assert_eq!(s.up.hits.load(Ordering::SeqCst), hits);
    assert_eq!(s.up.peak.load(Ordering::SeqCst), cap, "never more than the cap at the upstream");
    for h in slow {
        assert_eq!(h.join().unwrap().status, 200, "the calls in progress were not disturbed");
    }
    // the slots come back
    for _ in 0..(cap * 3) {
        assert_eq!(s.get("/crm/customers/c-1").status, 200);
    }
    assert!(Command::new(BIN).args(["http-proxy", "--routes", "x", "--max-concurrent", "0"]).output().map(|o| !o.status.success()).unwrap());
}

// ---- the daemon ------------------------------------------------------------------

struct Daemon {
    _tmp: Tmp,
    proc: Proc,
}

const ADMIN: &str = "admin-key-0123456789abcdef";
const PEP: &str = "pep-key-0123456789abcdef";

fn daemon(tag: &str, extra: Value) -> Daemon {
    let tmp = Tmp::new(tag);
    let mut cfg = json!({
        "bundle_dir": bundle().to_string_lossy(), "state_dir": tmp.0.join("state").to_string_lossy(),
        "admin_key": ADMIN, "pep_key": PEP, "listen": "127.0.0.1:0",
    });
    for (k, v) in extra.as_object().unwrap() {
        cfg[k] = v.clone();
    }
    let path = tmp.0.join("smartdelegate.json");
    std::fs::write(&path, cfg.to_string()).unwrap();
    let proc = Proc::start(&["serve", "--config", path.to_str().unwrap()]);
    Daemon { _tmp: tmp, proc }
}

/// A client that sends its headers and then stalls in the middle of the body.
fn stalled(addr: &str) -> TcpStream {
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(format!("POST /v1/authorize HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {PEP}\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n{{\"token\":").as_bytes()).unwrap();
    s
}

#[test]
fn stalled_clients_do_not_hold_up_the_daemon_and_the_cap_holds() {
    let cap = 8;
    let d = daemon("daemon", json!({"max_concurrent": cap}));
    let issue = json!({"user": "alice", "agent": "support-bot", "role": "support-agent"});
    assert_eq!(request(&d.proc.addr, "POST", "/v1/token", ADMIN, Some(&issue)).status, 200);
    // more stalled clients than the old pool had threads, fewer than the cap
    let mut held: Vec<TcpStream> = (0..cap - 1).map(|_| stalled(&d.proc.addr)).collect();
    std::thread::sleep(Duration::from_millis(300));
    let mut worst = Duration::ZERO;
    for _ in 0..20 {
        let r = request(&d.proc.addr, "POST", "/v1/token", ADMIN, Some(&issue));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.json()["role"], json!("support-agent"));
        worst = worst.max(r.took);
    }
    println!("worst issue_token with {} stalled clients: {worst:?}", cap - 1);
    assert!(worst < Duration::from_millis(300), "issue_token took {worst:?} behind stalled clients");

    // one more stalled client fills the last slot: the daemon refuses, promptly
    held.push(stalled(&d.proc.addr));
    std::thread::sleep(Duration::from_millis(300));
    for _ in 0..10 {
        let r = request(&d.proc.addr, "GET", "/v1/info", PEP, None);
        let e = r.json();
        assert_eq!((r.status, e["ok"].as_bool(), e["error"]["code"].as_str(), e["error"]["rule"].as_str()), (503, Some(false), Some("overloaded"), Some("DELEGATE-OVERLOADED")));
        assert!(r.took < Duration::from_millis(300));
    }
    // the stalled clients go away: their slots come back, and nothing they
    // half-sent was acted on
    drop(held);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let r = request(&d.proc.addr, "GET", "/v1/info", PEP, None);
        if r.status == 200 {
            assert_eq!(r.json()["implementation"], json!("rust"));
            break;
        }
        assert!(Instant::now() < deadline, "the slots never came back");
        std::thread::sleep(Duration::from_millis(50));
    }
    let v = request(&d.proc.addr, "GET", "/v1/admin/audit/verify", ADMIN, None);
    assert_eq!((v.status, v.json()["records"].as_u64()), (200, Some(21)), "only the 21 issued tokens are in the log");
}

/// Live finding L-9. With Nagle on, a response whose body is written after
/// its headers and does not fit with them waits for the client's delayed
/// ACK: token issuance took ~44 ms, against ~1 ms for a small `authorize`.
#[test]
fn token_issuance_over_rest_does_not_stall_on_nagle() {
    let d = daemon("nodelay", json!({}));
    let mut s = TcpStream::connect(&d.proc.addr).unwrap();
    s.set_nodelay(true).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut reader = BufReader::new(s.try_clone().unwrap());
    // keep-alive: every call on the one connection, as an enforcement point would
    let mut call = |path: &str, key: &str, body: &Value| -> (Duration, Value) {
        let payload = body.to_string();
        let started = Instant::now();
        s.write_all(format!("POST {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {key}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{payload}", payload.len()).as_bytes()).unwrap();
        let mut len = 0usize;
        loop {
            let mut l = String::new();
            assert!(reader.read_line(&mut l).unwrap() > 0, "connection closed");
            if l == "\r\n" {
                break;
            }
            if let Some(v) = l.to_ascii_lowercase().strip_prefix("content-length:") {
                len = v.trim().parse().unwrap();
            }
        }
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).unwrap();
        (started.elapsed(), serde_json::from_slice(&buf).unwrap())
    };
    let issue = json!({"user": "alice", "agent": "support-bot", "role": "support-agent"});
    let (_, t) = call("/v1/token", ADMIN, &issue);
    let token = t["token"].as_str().unwrap().to_string();
    let median = |mut v: Vec<Duration>| {
        v.sort();
        v[v.len() / 2]
    };
    let issued = median((0..41).map(|_| call("/v1/token", ADMIN, &issue).0).collect());
    let exchanged = median((0..41).map(|_| call("/v1/token", "", &json!({"subject_token": token, "actor": "refund-helper"})).0).collect());
    let authorized = median((0..41).map(|_| call("/v1/authorize", PEP, &json!({"token": token, "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}})).0).collect());
    println!("median over REST, one keep-alive connection: issue_token {issued:?}, exchange_token {exchanged:?}, authorize {authorized:?}");
    // the stall is 40 ms or more; without it these take a millisecond or two
    assert!(issued < Duration::from_millis(20), "issue_token median {issued:?}");
    assert!(exchanged < Duration::from_millis(20), "exchange_token median {exchanged:?}");
}

#[allow(dead_code)]
fn _unused(_: &Path) {}

// ---- the proxy's own rules at the edge of HTTP ------------------------------------

/// One request written byte for byte.
fn raw_request(addr: &str, bytes: &[u8]) -> Reply {
    let started = Instant::now();
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s.write_all(bytes).unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or_else(|| panic!("no response: {:?}", String::from_utf8_lossy(&raw)));
    let headers = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = headers.split(' ').nth(1).and_then(|x| x.parse().ok()).unwrap();
    Reply { status, headers, body: raw[split + 4..].to_vec(), took: started.elapsed() }
}

#[test]
fn a_query_the_proxy_cannot_read_one_way_gets_the_proxys_own_refusal() {
    let tmp = Tmp::new("edge");
    let up = upstream();
    let routes = tmp.0.join("routes.json");
    std::fs::write(
        &routes,
        json!({
            "upstreams": {"crm": {"base_url": "env:TEST_CRM_URL"}},
            "routes": [{"upstream": "crm", "method": "GET", "path": "/customers/{id}", "action": "read", "resource": "crm.customer", "id": "{id}", "query": ["q", "limit"],
                        "attrs_from_request": {"claimed": "query.q"}}],
        })
        .to_string(),
    )
    .unwrap();
    let common = ["--bundle".to_string(), bundle().to_string_lossy().to_string(), "--state".to_string(), tmp.0.join("state").to_string_lossy().to_string()];
    let out = Command::new(BIN).args(["token", "issue", "--user", "alice", "--agent", "support-bot", "--role", "support-agent", "--raw"]).args(&common).output().unwrap();
    let token = String::from_utf8(out.stdout).unwrap().trim().to_string();
    let mut child = Command::new(BIN)
        .args(["http-proxy", "--routes", routes.to_str().unwrap(), "--listen", "127.0.0.1:0"])
        .args(&common)
        .env("TEST_CRM_URL", format!("http://{}/", up.addr))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut err = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    err.read_line(&mut line).unwrap();
    // the listen line is first; the notes follow it
    assert!(line.starts_with("smartdelegate http proxy listening on http://"), "{line}");
    let addr = line.trim().rsplit("http://").next().unwrap().to_string();
    let mut note = String::new();
    err.read_line(&mut note).unwrap();
    assert_eq!(note.trim(), "smartdelegate http proxy: route 0 (GET /crm/customers/{id}) trusts request-supplied attributes: claimed");
    let proxy = Proc { child, addr };

    let get = |target: &[u8]| {
        let mut req = b"GET ".to_vec();
        req.extend_from_slice(target);
        req.extend_from_slice(format!(" HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n").as_bytes());
        raw_request(&proxy.addr, &req)
    };
    let code = |r: &Reply| (r.status, r.json()["error"]["code"].as_str().map(String::from), r.json()["error"]["by"].as_str().map(String::from));
    let refused = |c: &str| (400, Some(c.to_string()), Some("smartdelegate".to_string()));
    let hits = up.hits.load(Ordering::SeqCst);
    // raw bytes that are not ASCII: Latin-1, UTF-8, in a value and in a name
    assert_eq!(code(&get(b"/crm/customers/c-1?q=caf\xe9")), refused("query_ambiguous"));
    assert_eq!(code(&get(b"/crm/customers/c-1?q=caf\xc3\xa9")), refused("query_ambiguous"));
    assert_eq!(code(&get(b"/crm/customers/c-1?\xc3\xa9=1")), refused("query_ambiguous"));
    assert_eq!(code(&get(b"/crm/customers/c-1?q=1;limit=2")), refused("query_ambiguous"));
    assert_eq!(code(&get(b"/crm/customers/c-1?q=1&Q=2")), refused("query_not_allowed"));
    assert_eq!(code(&get(b"/crm/customers/c-1?q=1&limit=2&q=3")), refused("query_duplicate"));
    assert_eq!(code(&get(b"/crm/customers/c-1")), refused("invalid_input")); // the claimed attribute is missing
    assert_eq!(get(b"/crm/customers/c\xe9").status, 403); // no route: a parameter is ASCII
    assert_eq!(up.hits.load(Ordering::SeqCst), hits, "none of these reached the upstream");
    // methods are case-sensitive, and only the five the proxy mediates exist
    for m in ["get", "HEAD", "OPTIONS", "TRACE", "CONNECT"] {
        let r = raw_request(&proxy.addr, format!("{m} /crm/customers/c-1?q=1 HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n").as_bytes());
        assert_eq!(r.status, 501, "{m}");
        assert_eq!(r.body.is_empty(), m == "HEAD", "{m}: a HEAD answer has no body");
    }
    // not HTTP enough to route: refused, in the proxy's own shape
    for bad in [&b"GET /crm/customers/c 1 HTTP/1.1\r\n\r\n"[..], b"GET /crm/customers/c-1\r\n\r\n", b"GET /crm/customers/c-1 HTTP/2.0\r\n\r\n", b"GET /x HTTP/1.1\r\nbroken header\r\n\r\n"] {
        let r = raw_request(&proxy.addr, bad);
        assert_eq!(code(&r), refused("invalid_input"), "{}", String::from_utf8_lossy(bad));
    }
    let r = raw_request(&proxy.addr, format!("POST /crm/customers/c-1 HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nContent-Length: abc\r\n\r\n").as_bytes());
    assert_eq!(code(&r), refused("invalid_input"));
    // Framing, before anything else (also before the route: these go to a
    // path no route covers): a body is framed by exactly one numeric
    // Content-Length. Chunked bodies are not decoded, and whatever follows
    // on the connection is never read as a request.
    let smuggled = format!("GET /crm/customers/c-1?q=1 HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n\r\n");
    let chunk = "1a\r\n{\"email\": \"x@example.com\"}\r\n0\r\n\r\n";
    for (framing, status, want) in [
        ("Transfer-Encoding: chunked\r\n", 411, "length_required"),
        ("Transfer-Encoding: identity\r\n", 411, "length_required"),
        ("Transfer-Encoding: chunked\r\nContent-Length: 4\r\n", 400, "invalid_input"),
        ("Content-Length: 4\r\nTransfer-Encoding: chunked\r\n", 400, "invalid_input"),
        ("Content-Length: 0\r\nContent-Length: 0\r\n", 400, "invalid_input"),
        ("Content-Length: 5\r\ncontent-length: 5\r\n", 400, "invalid_input"),
        ("Content-Length: +5\r\n", 400, "invalid_input"),
        ("Content-Length: -1\r\n", 400, "invalid_input"),
        ("Content-Length: 0x10\r\n", 400, "invalid_input"),
        ("Content-Length: 5, 5\r\n", 400, "invalid_input"),
        ("Content-Length:\r\n", 400, "invalid_input"),
        ("Content-Length: 99999999999999999999999999\r\n", 400, "invalid_input"),
        ("Content-Length: 8388609\r\n", 400, "invalid_input"),
    ] {
        for path in ["/crm/customers/c-1", "/nowhere/at/all"] {
            let req = format!("PATCH {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\n{framing}\r\n{chunk}{smuggled}");
            let r = raw_request(&proxy.addr, req.as_bytes());
            let e = r.json(); // the whole of what came back is one JSON error: one response
            assert_eq!((r.status, e["error"]["code"].as_str(), e["error"]["by"].as_str()), (status, Some(want), Some("smartdelegate")), "{framing:?} {path}");
            assert!(r.headers.to_ascii_lowercase().contains("connection: close"), "{framing:?}: the connection is closed");
        }
    }
    let r = raw_request(&proxy.addr, format!("POST /crm/customers/c-1 HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nContent-Length: 9000000\r\n\r\n").as_bytes());
    assert_eq!(code(&r), refused("invalid_input"));
    assert_eq!(up.hits.load(Ordering::SeqCst), hits);

    // what is forwarded is the query as parsed, written out again; the base
    // URL comes from the environment (a trailing slash on it is dropped)
    let r = get(b"/crm/customers/c-1?limit=1&&q=a%20b+c%7e");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(up.last_target.lock().unwrap().as_str(), "/customers/c-1?limit=1&q=a%20b%2Bc~");
    // two requests on one connection
    let two = format!("GET /crm/customers/c-1?q=1 HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n\r\nGET /crm/customers/c-1?q=2 HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n");
    let r = raw_request(&proxy.addr, two.as_bytes());
    assert_eq!(r.status, 200);
    assert_eq!(String::from_utf8_lossy(&r.body).matches("HTTP/1.1 200 OK").count(), 1, "the second answer follows the first on the same connection");
    assert_eq!(up.last_target.lock().unwrap().as_str(), "/customers/c-1?q=2");
}

#[test]
fn a_routes_or_tools_file_the_proxy_cannot_stand_behind_stops_it_at_start() {
    let tmp = Tmp::new("refuse");
    let common = ["--bundle".to_string(), bundle().to_string_lossy().to_string(), "--state".to_string(), tmp.0.join("state").to_string_lossy().to_string()];
    let file = tmp.0.join("f.json");
    let run = |cmd: &[&str], tail: &[&str], doc: Value| {
        std::fs::write(&file, doc.to_string()).unwrap();
        let out = Command::new(BIN).args(cmd).args(&common).args(tail).stdin(Stdio::null()).output().unwrap();
        (out.status.code(), String::from_utf8_lossy(&out.stderr).to_string())
    };
    let f = file.to_str().unwrap();
    // the form used before 0.3: an attribute taken from the request under "attrs"
    let (code, err) = run(
        &["http-proxy", "--routes", f, "--listen", "127.0.0.1:0"],
        &[],
        json!({"upstreams": {"crm": {"base_url": "http://127.0.0.1:9"}}, "routes": [
            {"upstream": "crm", "method": "POST", "path": "/refunds", "action": "create", "resource": "billing.refund", "attrs": {"customer_owner": "body.customer_owner"}},
            {"upstream": "crm", "method": "GET", "path": "/c/{id}", "action": "read", "resource": "crm.customer", "attrs_from_record": {"region": "region"}}]}),
    );
    assert_eq!(code, Some(1), "{err}");
    assert!(err.starts_with("smartdelegate: the routes file is refused:\n  route 0 (POST /crm/refunds): attrs.customer_owner = \"body.customer_owner\" comes from the request"), "{err}");
    assert!(err.contains("attrs_from_request") && err.contains("\n  route 1 (GET /crm/c/{id}): \"attrs_from_record\" needs \"lookup\""), "{err}");
    assert!(!err.contains("listening"), "it did not start: {err}");
    let (code, err) = run(&["http-proxy", "--routes", f, "--listen", "127.0.0.1:0"], &[], json!({"routes": []}));
    assert_eq!(code, Some(1));
    assert!(err.contains("the routes file needs \"upstreams\" (an object) and \"routes\" (a list)"), "{err}");

    let (code, err) = run(
        &["mcp-proxy", "--tools", f],
        &["--", "true"],
        json!({"tools": {"update": {"action": "update", "resource": "crm.customer", "attrs": {"region": "args.region"}}}}),
    );
    assert_eq!(code, Some(1), "{err}");
    assert!(err.starts_with("smartdelegate: the tools file is refused:\n  tool update: attrs.region = \"args.region\" comes from the call's arguments"), "{err}");
}

#[test]
fn the_daemon_refuses_a_body_not_framed_by_one_content_length() {
    let d = daemon("framing", json!({}));
    let issue = json!({"user": "alice", "agent": "support-bot", "role": "support-agent"}).to_string();
    let chunked = format!("{:x}\r\n{issue}\r\n0\r\n\r\n", issue.len());
    let second = format!("POST /v1/token HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {ADMIN}\r\nContent-Length: {}\r\n\r\n{issue}", issue.len());
    for (framing, status, code) in [
        ("Transfer-Encoding: chunked\r\n", 411, "length_required"),
        ("Transfer-Encoding: chunked\r\nContent-Length: 3\r\n", 400, "invalid_input"),
        ("Content-Length: 3\r\nContent-Length: 3\r\n", 400, "invalid_input"),
        ("Content-Length: three\r\n", 400, "invalid_input"),
        ("Content-Length: 8388609\r\n", 400, "invalid_input"),
    ] {
        for (method, path) in [("POST", "/v1/token"), ("GET", "/healthz"), ("POST", "/no/such")] {
            let req = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {ADMIN}\r\n{framing}\r\n{chunked}{second}");
            let r = raw_request(&d.proc.addr, req.as_bytes());
            let e = r.json(); // one response: the request that followed was not read
            assert_eq!((r.status, e["ok"].as_bool(), e["error"]["code"].as_str()), (status, Some(false), Some(code)), "{framing:?} {method} {path}");
            assert!(e["error"]["rule"].is_string());
        }
    }
    // nothing was issued by any of them, and a well-framed request works
    let r = request(&d.proc.addr, "POST", "/v1/token", ADMIN, Some(&serde_json::from_str(&issue).unwrap()));
    assert_eq!(r.status, 200);
    let v = request(&d.proc.addr, "GET", "/v1/admin/audit/verify", ADMIN, None);
    assert_eq!(v.json()["records"].as_u64(), Some(1));
}
