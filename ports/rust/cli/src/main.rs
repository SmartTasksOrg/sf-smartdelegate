//! `smartdelegate`: one binary for the CLI, the decision daemon, the HTTP egress
//! proxy and the MCP proxy.

mod http;
mod httpproxy;
mod mcpproxy;
mod serve;
mod util;

use smartdelegate_core::{bundle, Engine};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use util::{die, json_arg, load_config, pretty, Args};

const HELP: &str = r#"smartdelegate - identity and access management for LLM agents

USAGE
  smartdelegate <command> [options]          JSON options accept @file, e.g. --cap @cap.json

SETUP
  init <dir>                            create a working directory with an example bundle
  info                                  version, policy version, mode, key id
  policy check                          load the bundle and report problems
  policy test                           run the bundle's tests/*.json
  bundle compile                        policies/*.cedar -> policies.json (the form every port loads)
  bundle keygen <prefix>                write <prefix>.key and <prefix>.pub (Ed25519)
  bundle sign --key <file>              sign the bundle (writes bundle.sig.json)

TOKENS
  token issue --user U --agent A (--cap JSON | --role R [--cap JSON]) [--groups g1,g2]
              [--ttl S] [--tenant T] [--task X] [--id-token JWT] [--raw]
                                        --role: lend the agent a role the user holds; the
                                        token can never carry more than the role allows
  token exchange --token T --actor A [--cap JSON] [--ttl S] [--raw]
  token inspect --token T
  token revoke --id TOKEN_ID | --token T | --user U     --user ends every token already
                                        issued for that human (offboarding)

DECISIONS
  authorize --token T --action A --resource path/id [--attrs JSON] [--context JSON]
            [--data JSON] [--strict] [--dry-run]      exit code 0 allow, 2 deny, 1 error
  explain   (same options)              show every check and every field decision
  approvals                             list held requests
  approve <approval_id> --by USER

AUDIT
  audit verify                          recompute the hash chain
  audit tail [-n N]

SERVERS
  serve [--listen 127.0.0.1:8181] [--max-concurrent N]       REST decision daemon
  http-proxy --routes FILE [--listen 127.0.0.1:8182] [--max-concurrent N]
                                        N requests in progress at once (default 256,
                                        or "max_concurrent" in the config of `serve`);
                                        beyond that: 503 overloaded, Retry-After: 1
  mcp-proxy --tools FILE [--token-file F] -- <mcp server command...>

OTHER
  call <op> [--input JSON|@file|-]      any operation of spec/API.md, JSON in, JSON out
  conformance <vectors dir> <bundle dir>
  bench [-n N] [--url http://host:port --pep-key K]

CONFIG
  --config FILE (or SMARTDELEGATE_CONFIG, or ./smartdelegate.json); --bundle DIR and --state DIR override it.
  --shadow logs would-be denials without enforcing them.
"#;

pub fn engine_from(args: &Args) -> (Engine, Value) {
    let cfg = load_config(args);
    match Engine::new(&cfg) {
        Ok(e) => (e, cfg),
        Err(e) => die(&e.to_string()),
    }
}

fn finish(v: Value) -> ! {
    println!("{}", pretty(&v));
    let code = if v["ok"] != json!(true) {
        1
    } else if v["effect"] == json!("deny") {
        2
    } else {
        0
    };
    std::process::exit(code)
}

fn decision_input(args: &Args) -> (Value, &'static str) {
    let res = args.req("resource");
    let (path, id) = res.split_once('/').unwrap_or((res.as_str(), "any"));
    let mut input = json!({"action": args.req("action"), "resource": {"path": path, "id": id}});
    if let Some(t) = args.flag("token") {
        input["token"] = json!(t);
    }
    if let Some(a) = args.flag("attrs") {
        input["resource"]["attrs"] = json_arg(&a);
    }
    if let Some(c) = args.flag("context") {
        input["context"] = json_arg(&c);
    }
    if args.has("strict") {
        input["strict"] = json!(true);
    }
    if args.has("dry-run") {
        input["dry_run"] = json!(true);
    }
    match args.flag("data") {
        Some(d) => {
            input["data"] = json_arg(&d);
            (input, "filter")
        }
        None => (input, "authorize"),
    }
}

const EXAMPLE: &[(&str, &str)] = &[
    ("catalog.json", include_str!("../../../../spec/conformance/bundle/catalog.json")),
    ("entities.json", include_str!("../../../../spec/conformance/bundle/entities.json")),
    ("policies.json", include_str!("../../../../spec/conformance/bundle/policies.json")),
    ("policies/delegation.cedar", include_str!("../../../../spec/conformance/bundle/policies/delegation.cedar")),
    ("policies/crm.cedar", include_str!("../../../../spec/conformance/bundle/policies/crm.cedar")),
    ("policies/billing.cedar", include_str!("../../../../spec/conformance/bundle/policies/billing.cedar")),
    ("policies/hr.cedar", include_str!("../../../../spec/conformance/bundle/policies/hr.cedar")),
    ("policies/roles.cedar", include_str!("../../../../spec/conformance/bundle/policies/roles.cedar")),
    ("roles.json", include_str!("../../../../spec/conformance/bundle/roles.json")),
    ("tests/basics.json", include_str!("../../../../spec/conformance/bundle/tests/basics.json")),
];

fn init(dir: &Path) {
    let cfg_path = dir.join("smartdelegate.json");
    if cfg_path.exists() {
        die(&format!("{} already exists; not overwriting", cfg_path.display()));
    }
    for (rel, body) in EXAMPLE {
        let p = dir.join("bundle").join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap_or_else(|e| die(&e.to_string()));
        std::fs::write(&p, body).unwrap_or_else(|e| die(&e.to_string()));
    }
    let cfg = json!({
        "bundle_dir": "bundle", "state_dir": "state", "issuer": "smartdelegate://local", "mode": "enforce",
        "listen": "127.0.0.1:8181", "admin_key": util::random_key(), "pep_key": util::random_key(),
    });
    std::fs::write(&cfg_path, pretty(&cfg)).unwrap_or_else(|e| die(&e.to_string()));
    println!("Created {}\n  bundle/   example policies, entities, roles and field catalog\n  state/    signing key, audit log (created on first use)\n\nNext:\n  cd {}\n  smartdelegate policy test\n  smartdelegate token issue --user alice --agent support-bot --role support-agent --raw\n  smartdelegate token issue --user alice --agent support-bot --cap @cap.json --raw", cfg_path.display(), dir.display());
    let cap = json!({"actions": ["read", "create", "update"], "resources": ["crm.customer/*", "billing.refund/*"], "budget": {"EUR": 20000}});
    let _ = std::fs::write(dir.join("cap.json"), pretty(&cap));
}

fn conformance(vectors: &Path, bundle_dir: &Path) -> ! {
    let mut files: Vec<PathBuf> = std::fs::read_dir(vectors).unwrap_or_else(|e| die(&e.to_string())).filter_map(|e| e.ok().map(|e| e.path())).collect();
    files.sort();
    let (mut total, mut failed) = (0, 0);
    for f in files.iter().filter(|f| f.extension().map(|x| x == "json").unwrap_or(false)) {
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap_or_else(|e| die(&e.to_string()));
        for (i, case) in doc["cases"].as_array().cloned().unwrap_or_default().iter().enumerate() {
            let state = std::env::temp_dir().join(format!("smartdelegate-cli-conf-{}-{}", std::process::id(), total + i));
            let _ = std::fs::remove_dir_all(&state);
            let mut engine = Engine::new(&smartdelegate_core::conformance::case_config(bundle_dir, &state, &doc)).unwrap_or_else(|e| die(&e.to_string()));
            let r = smartdelegate_core::conformance::run_case(&mut engine, case);
            total += 1;
            if r["passed"] != json!(true) {
                failed += 1;
                println!("FAIL {}\n{}", case["name"], pretty(&r["failures"]));
            }
            let _ = std::fs::remove_dir_all(&state);
        }
    }
    println!("conformance: {} cases, {} failed", total, failed);
    std::process::exit(if failed == 0 { 0 } else { 1 })
}

fn main() {
    let args = Args::parse(std::env::args().skip(1).collect());
    let cmd = args.pos.first().map(|s| s.as_str()).unwrap_or("help");
    let sub = args.pos.get(1).map(|s| s.as_str()).unwrap_or("");
    match (cmd, sub) {
        ("help", _) | ("--help", _) | ("-h", _) => print!("{HELP}"),
        ("version", _) => println!("smartdelegate {}", smartdelegate_core::VERSION),
        ("init", d) if !d.is_empty() => init(Path::new(d)),
        ("info", _) => finish(engine_from(&args).0.call("info", &json!({}))),
        ("policy", "check") => {
            let (mut e, _) = engine_from(&args);
            let info = e.call("info", &json!({}));
            println!("bundle loads: {} policies, version {}", info["policies"], info["policy_version"].as_str().unwrap_or(""));
        }
        ("policy", "test") => {
            let cfg = load_config(&args);
            let dir = PathBuf::from(cfg["bundle_dir"].as_str().unwrap_or("bundle"));
            match smartdelegate_core::conformance::run_bundle_tests(&dir) {
                Ok(r) => {
                    for c in r["results"].as_array().unwrap() {
                        println!("{} {}", if c["passed"] == json!(true) { "ok  " } else { "FAIL" }, c["name"].as_str().unwrap_or("?"));
                        if c["passed"] != json!(true) {
                            println!("{}", pretty(&c["failures"]));
                        }
                    }
                    println!("{} tests, {} failed", r["total"], r["failed"]);
                    std::process::exit(if r["failed"] == json!(0) { 0 } else { 1 });
                }
                Err(e) => die(&e.to_string()),
            }
        }
        ("bundle", "keygen") => {
            let prefix = args.pos.get(2).cloned().unwrap_or_else(|| die("usage: smartdelegate bundle keygen <prefix>"));
            let (sk, pk) = bundle::keygen().unwrap_or_else(|e| die(&e.to_string()));
            std::fs::write(format!("{prefix}.key"), &sk).unwrap_or_else(|e| die(&e.to_string()));
            std::fs::write(format!("{prefix}.pub"), &pk).unwrap_or_else(|e| die(&e.to_string()));
            println!("wrote {prefix}.key (keep secret) and {prefix}.pub\nset \"bundle_public_key\": \"{pk}\" in smartdelegate.json to require signed bundles");
        }
        ("bundle", "compile") => {
            let cfg = load_config(&args);
            match bundle::compile(Path::new(cfg["bundle_dir"].as_str().unwrap_or("bundle"))) {
                Ok(v) => println!("wrote policies.json ({} policies)", v["policies"].as_object().map(|o| o.len()).unwrap_or(0)),
                Err(e) => die(&e.to_string()),
            }
        }
        ("bundle", "sign") => {
            let cfg = load_config(&args);
            let key = std::fs::read_to_string(args.req("key")).unwrap_or_else(|e| die(&e.to_string()));
            match bundle::sign(Path::new(cfg["bundle_dir"].as_str().unwrap_or("bundle")), &key) {
                Ok(v) => println!("signed bundle version {} with key {}", v["version"].as_str().unwrap_or(""), v["key_id"].as_str().unwrap_or("")),
                Err(e) => die(&e.to_string()),
            }
        }
        ("token", "issue") => {
            let (mut e, _) = engine_from(&args);
            let mut input = json!({"agent": args.req("agent")});
            match args.flag("cap") {
                Some(c) => input["cap"] = json_arg(&c),
                None if args.has("role") => {}
                None => die("--cap JSON or --role NAME is required"),
            }
            for k in ["user", "tenant", "task", "role"] {
                if let Some(v) = args.flag(k).filter(|v| !v.is_empty()) {
                    input[k] = json!(v);
                }
            }
            if let Some(g) = args.flag("groups") {
                // live membership for this token; an empty value means "member of nothing"
                input["groups"] = json!(g.split(',').filter(|x| !x.is_empty()).collect::<Vec<_>>());
            }
            if let Some(v) = args.flag("id-token") {
                input["id_token"] = json!(v);
            }
            if let Some(t) = args.flag("ttl") {
                input["ttl"] = json!(t.parse::<i64>().unwrap_or_else(|_| die("--ttl must be a number of seconds")));
            }
            token_out(e.call("issue_token", &input), &args)
        }
        ("token", "exchange") => {
            let (mut e, _) = engine_from(&args);
            let mut input = json!({"subject_token": args.req("token"), "actor": args.req("actor")});
            if let Some(c) = args.flag("cap") {
                input["cap"] = json_arg(&c);
            }
            if let Some(t) = args.flag("ttl") {
                input["ttl"] = json!(t.parse::<i64>().unwrap_or_else(|_| die("--ttl must be a number of seconds")));
            }
            token_out(e.call("exchange_token", &input), &args)
        }
        ("token", "inspect") => finish(engine_from(&args).0.call("inspect_token", &json!({"token": args.req("token")}))),
        ("token", "revoke") => {
            let input = match (args.flag("user").filter(|u| !u.is_empty()), args.flag("id").filter(|i| !i.is_empty())) {
                (Some(user), _) => json!({"user": user, "by": "cli"}),
                (None, Some(id)) => json!({"token_id": id, "by": "cli"}),
                (None, None) => json!({"token": args.req("token"), "by": "cli"}),
            };
            finish(engine_from(&args).0.call("revoke", &input))
        }
        ("call", op) if !op.is_empty() => {
            // any operation, input as JSON: the form other ports and scripts use
            let raw = args.flag("input").filter(|r| !r.is_empty()).unwrap_or_else(|| "{}".into());
            let input = if raw == "-" {
                let mut text = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut text).unwrap_or_else(|e| die(&e.to_string()));
                serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap_or_else(|e| die(&format!("not valid JSON on stdin ({e})")))
            } else {
                json_arg(&raw)
            };
            finish(engine_from(&args).0.call(op, &input))
        }
        ("authorize", _) => {
            let (input, op) = decision_input(&args);
            finish(engine_from(&args).0.call(op, &input))
        }
        ("explain", _) => {
            let (input, _) = decision_input(&args);
            finish(engine_from(&args).0.call("explain", &input))
        }
        ("approvals", _) => finish(engine_from(&args).0.call("approvals", &json!({}))),
        ("approve", id) if !id.is_empty() => finish(engine_from(&args).0.call("approve", &json!({"approval_id": id, "by": args.req("by")}))),
        ("audit", "verify") => finish(engine_from(&args).0.call("audit_verify", &json!({}))),
        ("audit", "tail") => {
            let n: u64 = args.flag("n").and_then(|x| x.parse().ok()).unwrap_or(20);
            let r = engine_from(&args).0.call("audit_tail", &json!({"n": n}));
            for rec in r["records"].as_array().cloned().unwrap_or_default() {
                println!("{rec}");
            }
        }
        ("serve", _) => serve::run(&args),
        ("http-proxy", _) => httpproxy::run(&args),
        ("mcp-proxy", _) => mcpproxy::run(&args),
        ("conformance", v) if !v.is_empty() => conformance(Path::new(v), Path::new(args.pos.get(2).map(|s| s.as_str()).unwrap_or("conformance/bundle"))),
        ("spec", "eval-gen") => {
            let src = util::json_arg(&format!("@{}", args.pos.get(2).cloned().unwrap_or_else(|| die("usage: smartdelegate spec eval-gen <cases.src.json> <cases.json>"))));
            let out = args.pos.get(3).cloned().unwrap_or_else(|| die("usage: smartdelegate spec eval-gen <cases.src.json> <cases.json>"));
            match smartdelegate_core::evalspec::generate(&src) {
                Ok(doc) => {
                    std::fs::write(&out, pretty(&doc) + "\n").unwrap_or_else(|e| die(&e.to_string()));
                    println!("wrote {} ({} cases)", out, doc["cases"].as_array().map(|a| a.len()).unwrap_or(0));
                }
                Err(e) => die(&e.to_string()),
            }
        }
        ("bench", _) => util::bench(&args),
        _ => {
            eprint!("{HELP}");
            std::process::exit(1)
        }
    }
}

fn token_out(v: Value, args: &Args) -> ! {
    if args.has("raw") && v["ok"] == json!(true) {
        println!("{}", v["token"].as_str().unwrap_or(""));
        std::process::exit(0)
    }
    finish(v)
}
