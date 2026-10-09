//! Stable C ABI. Four functions; every payload is a NUL-terminated UTF-8 JSON
//! string. See include/smartdelegate.h.

use crate::Engine;
use serde_json::Value;
use std::ffi::{c_char, CStr, CString};
use std::sync::Mutex;

pub struct Handle {
    engine: Mutex<Engine>,
}

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<CString>> = const { std::cell::RefCell::new(None) };
}

fn to_c(v: &Value) -> *mut c_char {
    // serde_json never emits interior NULs (they are escaped as \u0000)
    CString::new(v.to_string()).map(|c| c.into_raw()).unwrap_or(std::ptr::null_mut())
}

unsafe fn read(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok().map(String::from)
}

/// Create an engine from a JSON config. Returns NULL on failure; call
/// `smartdelegate_last_error` on the same thread for the reason.
#[no_mangle]
pub unsafe extern "C" fn smartdelegate_engine_new(config_json: *const c_char) -> *mut Handle {
    let result = std::panic::catch_unwind(|| {
        let text = read(config_json).ok_or_else(|| crate::Error::new("invalid_input", "config is not UTF-8"))?;
        let cfg: Value = serde_json::from_str(&text).map_err(|e| crate::Error::new("invalid_input", format!("config: {e}")))?;
        Engine::new(&cfg)
    });
    let err = match result {
        Ok(Ok(engine)) => return Box::into_raw(Box::new(Handle { engine: Mutex::new(engine) })),
        Ok(Err(e)) => e.to_json(),
        Err(_) => crate::Error::new("panic", "internal error").to_json(),
    };
    LAST_ERROR.with(|l| *l.borrow_mut() = CString::new(err.to_string()).ok());
    std::ptr::null_mut()
}

/// JSON error of the last failed `smartdelegate_engine_new` on this thread, or
/// NULL. The pointer stays valid until the next call on this thread; do not
/// free it.
#[no_mangle]
pub extern "C" fn smartdelegate_last_error() -> *const c_char {
    LAST_ERROR.with(|l| l.borrow().as_ref().map(|c| c.as_ptr()).unwrap_or(std::ptr::null()))
}

/// Run one operation. Always returns a JSON string (never NULL unless out of
/// memory); free it with `smartdelegate_string_free`. Safe to call from several
/// threads: calls on one handle are serialised.
#[no_mangle]
pub unsafe extern "C" fn smartdelegate_call(handle: *mut Handle, op: *const c_char, input_json: *const c_char) -> *mut c_char {
    if handle.is_null() {
        return to_c(&crate::Error::new("invalid_handle", "engine handle is NULL").to_json());
    }
    let h = &*handle;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let op = match read(op) {
            Some(o) => o,
            None => return crate::Error::new("invalid_input", "op is not UTF-8").to_json(),
        };
        let input: Value = match read(input_json).map(|t| serde_json::from_str(&t)) {
            Some(Ok(v)) => v,
            _ => return crate::Error::new("invalid_input", "input is not valid JSON").to_json(),
        };
        // A panic while holding the lock poisons it; later calls then fail
        // closed with an error instead of continuing on a half-updated engine.
        match h.engine.lock() {
            Ok(mut e) => e.call(&op, &input),
            Err(_) => crate::Error::new("poisoned", "engine is unusable after an internal error").to_json(),
        }
    }));
    to_c(&result.unwrap_or_else(|_| crate::Error::new("panic", "internal error").to_json()))
}

#[no_mangle]
pub unsafe extern "C" fn smartdelegate_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

#[no_mangle]
pub unsafe extern "C" fn smartdelegate_engine_free(handle: *mut Handle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

#[no_mangle]
pub extern "C" fn smartdelegate_abi_version() -> u32 {
    1
}
