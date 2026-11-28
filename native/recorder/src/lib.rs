//! Narrow Windows x64 ABI over ProxyLane's per-recording runtime. A tap owns an Arc
//! to its runtime. GuestGate serializes calls and releases taps before finalizing.
use proxylane_mitm::protocol::{Runtime, Tap};
use proxylane_protocol::{cache::CacheConfig, recording::RecordingConfig, Connection};
use std::{
    ffi::{c_char, CStr},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
    sync::Arc,
};

unsafe fn text<'a>(p: *const c_char) -> Result<&'a str, String> {
    CStr::from_ptr(p).to_str().map_err(|e| e.to_string())
}
unsafe fn output(out: *mut u8, cap: usize, value: &str) {
    let n = value.len().min(cap - 1);
    ptr::copy_nonoverlapping(value.as_ptr(), out, n);
    *out.add(n) = 0;
}
#[no_mangle]
pub unsafe extern "C" fn gg_record_start(
    root: *const c_char,
    out: *mut u8,
    cap: usize,
) -> *mut Arc<Runtime> {
    let res = catch_unwind(AssertUnwindSafe(|| -> Result<_, String> {
        let config = CacheConfig {
            root: text(root)?.into(),
            queue_chunks: 1024,
            recording: Some(RecordingConfig {
                total_bytes: 8 << 30,
                min_free_bytes: 512 << 20,
            }),
            ..Default::default()
        };
        let runtime = Runtime::new(config)?;
        runtime.start_capture();
        let status = runtime.recording_status();
        let directory = status["directory"]
            .as_str()
            .ok_or("missing recording directory")?;
        if directory.len() >= cap {
            return Err("recording path too long".into());
        }
        output(out, cap, directory);
        Ok(Box::into_raw(Box::new(runtime)))
    }));
    match res {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            output(out, cap, &e);
            ptr::null_mut()
        }
        Err(_) => {
            output(out, cap, "recording initialization failed");
            ptr::null_mut()
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn gg_record_status(r: *mut Arc<Runtime>, out: *mut u8, cap: usize) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let s = (*r).recording_status();
        if s["stopped"] == true {
            output(
                out,
                cap,
                s["reason"].as_str().unwrap_or("recording stopped"),
            );
            return -1;
        }
        0
    }))
    .unwrap_or(-1)
}
#[no_mangle]
pub unsafe extern "C" fn gg_record_stop(r: *mut Arc<Runtime>, out: *mut u8, cap: usize) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let r = Box::from_raw(r);
        let result = r.stop_capture().and_then(|_| r.shutdown());
        if let Err(e) = result {
            output(out, cap, &e);
            return -1;
        }
        0
    }))
    .unwrap_or(-1)
}
#[no_mangle]
pub unsafe extern "C" fn gg_tap_open(
    r: *mut Arc<Runtime>,
    id: u64,
    dst: *const c_char,
    name: *const c_char,
    alpn: *const c_char,
    port: u16,
    mode: u32,
) -> *mut Tap {
    catch_unwind(AssertUnwindSafe(|| {
        let alpn = text(alpn).ok()?;
        let c = Connection {
            id: id.to_string(),
            destination: text(dst).ok()?.into(),
            server_name: text(name).ok()?.into(),
            server_port: port,
            transport: if mode & 3 == 2 { "udp" } else { "tcp" }.into(),
            ..Default::default()
        };
        let mut t = (*r).tap_transport(
            c,
            (!alpn.is_empty()).then(|| alpn.as_bytes().to_vec()),
            mode & 3 == 1,
        )?;
        if mode & 4 == 0 {
            t.transport_result(0);
        }
        Some(Box::into_raw(Box::new(t)))
    }))
    .ok()
    .flatten()
    .unwrap_or(ptr::null_mut())
}
#[no_mangle]
pub unsafe extern "C" fn gg_tap_event(
    t: *mut Tap,
    op: u32,
    side: usize,
    p: *const u8,
    n: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let bytes = if n == 0 {
            &[]
        } else {
            slice::from_raw_parts(p, n)
        };
        match op {
            0 => (*t).data(side, bytes),
            1 => (*t).datagram(side, bytes),
            2 => (*t).eof(side, true),
            3 => {
                if !bytes.is_empty() {
                    (*t).close_reason(String::from_utf8_lossy(bytes).into_owned())
                }
                drop(Box::from_raw(t))
            }
            4 => (*t).note(String::from_utf8_lossy(bytes).into_owned()),
            _ => return -1,
        }
        0
    }))
    .unwrap_or(-1)
}

// Concatenated DER from the same Mozilla bundle used by ProxyLane. Verification
// never retrieves intermediates or CRLs from URLs controlled by a sample.
#[no_mangle]
pub unsafe extern "C" fn gg_roots(out: *mut u8, cap: usize) -> usize {
    let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS;
    let size = roots.iter().map(|cert| cert.len()).sum();
    if !out.is_null() && cap >= size {
        let mut pos = out;
        for cert in roots {
            ptr::copy_nonoverlapping(cert.as_ptr(), pos, cert.len());
            pos = pos.add(cert.len());
        }
    }
    size
}
