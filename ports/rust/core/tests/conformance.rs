//! Runs every shared conformance vector against the core directly.
use serde_json::{json, Value};
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("..").join("spec").join("conformance")
}

#[test]
fn conformance_vectors() {
    let mut files: Vec<_> = std::fs::read_dir(root().join("vectors")).unwrap().map(|e| e.unwrap().path()).collect();
    files.sort();
    assert!(!files.is_empty());
    let (mut total, mut steps, mut failed) = (0, 0, vec![]);
    for f in files {
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(&f).unwrap()).unwrap();
        for (i, case) in doc["cases"].as_array().unwrap().iter().enumerate() {
            let state = std::env::temp_dir().join(format!("smartdelegate-conf-{}-{}-{}", std::process::id(), doc["suite"].as_str().unwrap(), i));
            let _ = std::fs::remove_dir_all(&state);
            let mut engine = smartdelegate_core::Engine::new(&smartdelegate_core::conformance::case_config(&root().join("bundle"), &state, &doc)).expect("engine");
            let r = smartdelegate_core::conformance::run_case(&mut engine, case);
            total += 1;
            steps += case["steps"].as_array().map(|a| a.len()).unwrap_or(0);
            if r["passed"] != json!(true) {
                failed.push(r);
            }
            let _ = std::fs::remove_dir_all(&state);
        }
    }
    assert!(failed.is_empty(), "{} of {} cases failed:\n{}", failed.len(), total, serde_json::to_string_pretty(&failed).unwrap());
    // the suite as of spec 0.3; a runner that silently skipped files would pass
    assert!(total >= 78 && steps >= 327, "only {steps} steps were found");
    assert!(total >= 78, "only {total} conformance cases were found");
    println!("{total} conformance cases ({steps} steps) passed");
}

/// The policy-evaluation vectors must be exactly what real Cedar answers.
#[test]
fn eval_vectors_match_real_cedar() {
    let path = root().join("eval").join("cases.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let bad = smartdelegate_core::evalspec::verify(&doc).unwrap();
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    let n = doc["cases"].as_array().unwrap().len();
    // the suite as of spec 0.3
    assert!(n >= 95, "only {n} eval cases were found");
    println!("{n} eval cases match real Cedar");
}

/// The compiled example bundle must match its Cedar sources (loading checks it).
#[test]
fn compiled_bundle_is_current() {
    smartdelegate_core::Engine::new(&json!({"bundle_dir": root().join("bundle").to_string_lossy()})).expect("bundle loads and policies.json is current");
}
