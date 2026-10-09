//! The HTTP/1.1 server under the daemon and the HTTP proxy.
//!
//! Small on purpose, and ours, because an enforcement point has to decide
//! itself what it does with a request another server would quietly repair
//! or drop:
//!   - the request target is handed on byte for byte (each byte one
//!     character), so a raw non-ASCII byte in a query is refused by the
//!     proxy's own rule with its own answer, not by a library;
//!   - TCP_NODELAY is set on every accepted connection (a response written
//!     after Nagle's algorithm holds it back costs ~40 ms per call);
//!   - every connection has a thread of its own, so a request that waits
//!     holds up nobody else; the number of requests in progress and the
//!     number of connections are both capped; and a client that stops
//!     sending is dropped after a timeout.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_HEAD: usize = 64 * 1024;
/// How long a client may take to send the next piece of a request, and how
/// long an idle keep-alive connection is kept.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);
/// Connections beyond the requests in progress (idle keep-alive ones).
const EXTRA_CONNECTIONS: usize = 1024;

pub struct Request {
    /// As sent: methods are case-sensitive.
    pub method: String,
    /// The request target, each byte as one character (ISO 8859-1): what is
    /// not ASCII stays visible as what it is.
    pub target: String,
    headers: Vec<(String, String)>,
    /// The body, or why none was read. After a refusal the connection is
    /// closed: nothing that follows on it is read as a request.
    pub body: Result<Vec<u8>, BadFraming>,
}

/// A request whose length is not stated by exactly one numeric
/// `Content-Length` of at most 8 MiB. Chunked bodies are not decoded: a
/// server in front of us and we could disagree about where such a request
/// ends.
#[derive(Clone, Debug)]
pub struct BadFraming {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

impl Request {
    /// The first header of that name (names compare without regard to case).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    /// The credential of `Authorization: Bearer <credential>`.
    pub fn bearer(&self) -> Option<String> {
        self.header("Authorization").and_then(|h| h.strip_prefix("Bearer ")).map(|s| s.trim().to_string())
    }
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, content_type: Option<&str>, body: Vec<u8>) -> Response {
        Response { status, headers: content_type.map(|c| vec![("Content-Type".to_string(), c.to_string())]).unwrap_or_default(), body }
    }
    pub fn json(status: u16, body: &serde_json::Value) -> Response {
        Response::new(status, Some("application/json"), body.to_string().into_bytes())
    }
    pub fn with_header(mut self, name: &str, value: &str) -> Response {
        // a header value is one line
        if !value.bytes().any(|b| b == b'\r' || b == b'\n') {
            self.headers.push((name.to_string(), value.to_string()));
        }
        self
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

/// `head_only`: the answer to a HEAD request carries no body.
fn write_response_to(stream: &mut TcpStream, r: &Response, close: bool, head_only: bool) -> std::io::Result<()> {
    if head_only {
        return write_response(stream, &Response { status: r.status, headers: r.headers.clone(), body: Vec::new() }, close);
    }
    write_response(stream, r, close)
}

fn write_response(stream: &mut TcpStream, r: &Response, close: bool) -> std::io::Result<()> {
    let mut head = format!("HTTP/1.1 {} {}\r\nServer: smartdelegate\r\n", r.status, reason(r.status));
    for (k, v) in &r.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n", r.body.len()));
    if close {
        head.push_str("Connection: close\r\n");
    }
    head.push_str("\r\n");
    // one write for a small response: head and body leave together
    let mut out = head.into_bytes();
    if r.body.len() <= 64 * 1024 {
        out.extend_from_slice(&r.body);
        stream.write_all(&out)?;
    } else {
        stream.write_all(&out)?;
        stream.write_all(&r.body)?;
    }
    stream.flush()
}

pub struct Server {
    listener: TcpListener,
}

struct Counted(Arc<AtomicUsize>);

impl Counted {
    /// Takes one of `max`, or `None` when all are taken.
    fn take(counter: &Arc<AtomicUsize>, max: usize) -> Option<Counted> {
        if counter.fetch_add(1, Ordering::SeqCst) >= max {
            counter.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Counted(counter.clone()))
    }
}

impl Drop for Counted {
    // also when a handler panics: a slot is never leaked
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

enum Head {
    /// The connection is finished (closed, idle too long, or unusable).
    Done,
    /// Answer this and close.
    Refuse(u16, &'static str),
    Request { method: String, target: String, headers: Vec<(String, String)>, keep_alive: bool },
}

/// Bytes read from the connection but not used yet.
struct Conn {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Conn {
    fn fill(&mut self) -> std::io::Result<usize> {
        let mut chunk = [0u8; 16 * 1024];
        let n = self.stream.read(&mut chunk)?;
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n)
    }

    fn take(&mut self, n: usize) -> Vec<u8> {
        let rest = self.buf.split_off(n);
        std::mem::replace(&mut self.buf, rest)
    }

    fn read_head(&mut self) -> Head {
        loop {
            // blank lines before a request line are skipped
            while self.buf.starts_with(b"\r\n") {
                self.buf.drain(..2);
            }
            if let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = self.take(end + 4);
                return parse_head(&head[..end]);
            }
            if self.buf.len() > MAX_HEAD {
                return Head::Refuse(431, "the request head is too large");
            }
            match self.fill() {
                Ok(0) | Err(_) => return if self.buf.is_empty() { Head::Done } else { Head::Refuse(408, "the request was not completed in time") },
                Ok(_) => {}
            }
        }
    }

    fn read_exact(&mut self, n: usize) -> Option<Vec<u8>> {
        while self.buf.len() < n {
            if !matches!(self.fill(), Ok(k) if k > 0) {
                return None;
            }
        }
        Some(self.take(n))
    }

    /// `Some(Ok(body))`, `Some(Err(why))` when the framing is refused (the
    /// connection cannot be used again), `None` when the client went away.
    fn read_body(&mut self, headers: &[(String, String)]) -> Option<Result<Vec<u8>, BadFraming>> {
        let all = |name: &str| headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string()).collect::<Vec<_>>();
        let bad = |status: u16, code: &'static str, message: &str| Some(Err(BadFraming { status, code, message: message.to_string() }));
        let lengths = all("Content-Length");
        if !all("Transfer-Encoding").is_empty() {
            if !lengths.is_empty() {
                return bad(400, "invalid_input", "a request with both Transfer-Encoding and Content-Length is refused");
            }
            return bad(411, "length_required", "send the body with Content-Length; Transfer-Encoding is not accepted");
        }
        if lengths.len() > 1 || lengths.first().map(|l| l.is_empty() || !l.bytes().all(|b| b.is_ascii_digit())).unwrap_or(false) {
            return bad(400, "invalid_input", "Content-Length must appear once and be a number");
        }
        // digits only; a number too long to parse is certainly too large
        let n = lengths.first().map(|l| l.parse::<usize>().unwrap_or(usize::MAX)).unwrap_or(0);
        if n > MAX_BODY {
            return bad(400, "invalid_input", "request body is too large");
        }
        if n == 0 {
            return Some(Ok(Vec::new()));
        }
        if all("Expect").iter().any(|e| e.eq_ignore_ascii_case("100-continue")) {
            let _ = self.stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        }
        self.read_exact(n).map(Ok)
    }
}

fn parse_head(head: &[u8]) -> Head {
    // each byte one character: nothing is repaired, nothing is lost
    let text: String = head.iter().map(|b| *b as char).collect();
    let mut lines = text.split("\r\n");
    let words: Vec<&str> = lines.next().unwrap_or("").split_ascii_whitespace().collect();
    let [method, target, version] = words[..] else { return Head::Refuse(400, "bad request line") };
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Head::Refuse(400, "bad request version");
    }
    let mut headers = Vec::new();
    for line in lines {
        match line.split_once(':') {
            Some((k, v)) if !k.is_empty() && !k.contains(|c: char| c.is_ascii_whitespace()) => headers.push((k.to_string(), v.trim().to_string())),
            _ => return Head::Refuse(400, "bad header line"),
        }
    }
    let connection = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("Connection")).map(|(_, v)| v.to_ascii_lowercase()).unwrap_or_default();
    let keep_alive = if version == "HTTP/1.0" { connection.contains("keep-alive") } else { !connection.contains("close") };
    Head::Request { method: method.to_string(), target: target.to_string(), headers, keep_alive }
}

impl Server {
    /// Binds; `None` with the reason on failure.
    pub fn bind(listen: &str) -> Result<Server, String> {
        TcpListener::bind(listen).map(|listener| Server { listener }).map_err(|e| e.to_string())
    }

    pub fn addr(&self) -> String {
        self.listener.local_addr().map(|a: SocketAddr| a.to_string()).unwrap_or_default()
    }

    /// Serves until the listener fails. At most `max` requests are in
    /// progress at once: one that arrives beyond that is answered with
    /// `busy()` at once, it is not queued. `refuse(status, message)` words
    /// the answer to a request that is not HTTP enough to be handled.
    pub fn serve<H, B, R>(self, max: usize, handle: H, busy: B, refuse: R)
    where
        H: Fn(Request) -> Response + Send + Sync + 'static,
        B: Fn() -> Response + Send + Sync + 'static,
        R: Fn(u16, &str) -> Response + Send + Sync + 'static,
    {
        let (handle, busy, refuse) = (Arc::new(handle), Arc::new(busy), Arc::new(refuse));
        let (requests, connections) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        for stream in self.listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_nodelay(true);
            let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
            let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
            let Some(conn_slot) = Counted::take(&connections, max.saturating_add(EXTRA_CONNECTIONS)) else {
                let _ = write_response(&mut stream, &busy(), true);
                continue;
            };
            let (handle, their_busy, refuse, requests) = (handle.clone(), busy.clone(), refuse.clone(), requests.clone());
            let Ok(mut spare) = stream.try_clone() else { continue };
            let spawned = std::thread::Builder::new().name("connection".into()).stack_size(512 * 1024).spawn(move || {
                let _conn_slot = conn_slot;
                let mut conn = Conn { stream, buf: Vec::new() };
                loop {
                    let (method, target, headers, keep_alive) = match conn.read_head() {
                        Head::Done => return,
                        Head::Refuse(status, why) => {
                            let _ = write_response(&mut conn.stream, &refuse(status, why), true);
                            return;
                        }
                        Head::Request { method, target, headers, keep_alive } => (method, target, headers, keep_alive),
                    };
                    // the slot is held from here to the end of the response,
                    // the reading of the body included
                    let Some(_slot) = Counted::take(&requests, max) else {
                        let _ = write_response(&mut conn.stream, &their_busy(), true);
                        return;
                    };
                    let Some(body) = conn.read_body(&headers) else { return };
                    let reusable = keep_alive && body.is_ok();
                    let head_only = method == "HEAD";
                    let req = Request { method, target, headers, body };
                    // a panic in one request must not take the process down
                    let resp = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle(req))).unwrap_or_else(|_| refuse(500, "internal error"));
                    if write_response_to(&mut conn.stream, &resp, !reusable, head_only).is_err() || !reusable {
                        return;
                    }
                }
            });
            if spawned.is_err() {
                // the system would not give us a thread: refuse, do not crash
                let _ = write_response(&mut spare, &busy(), true);
            }
        }
    }
}
