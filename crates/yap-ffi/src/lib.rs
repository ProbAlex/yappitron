//! C ABI over [`yap_core::api::call`]. Two functions, no state of their own.
//!
//! Dart calls `yap_call` with a request buffer and gets back a heap buffer it must release
//! with `yap_free`. See `yap_core::api` for the request/response format.

use std::panic::{AssertUnwindSafe, catch_unwind};

/// Run one request and return the response buffer; its length is written to `out_len`.
///
/// # Safety
/// `req` must point to `len` readable bytes (it may be null only if `len` is 0) and `out_len`
/// must be a valid, writable pointer. The returned buffer must be freed with [`yap_free`]
/// using the same length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn yap_call(req: *const u8, len: usize, out_len: *mut usize) -> *mut u8 {
    let request: &[u8] = if len == 0 || req.is_null() {
        &[]
    } else {
        // SAFETY: the caller guarantees `req` is valid for `len` bytes.
        unsafe { std::slice::from_raw_parts(req, len) }
    };
    // A panic must never unwind into Dart; report it as an ordinary error response.
    let response = catch_unwind(AssertUnwindSafe(|| yap_core::api::call(request)))
        .unwrap_or_else(|_| yap_core::api::error_response("internal error"));
    let boxed = response.into_boxed_slice();
    // SAFETY: the caller guarantees `out_len` is valid and writable.
    unsafe { *out_len = boxed.len() };
    Box::into_raw(boxed) as *mut u8
}

/// Release a buffer returned by [`yap_call`].
///
/// # Safety
/// `ptr` and `len` must be exactly what `yap_call` returned/wrote, and each buffer may be
/// freed only once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn yap_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        // SAFETY: per the contract above this is the original boxed slice.
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_the_c_abi() {
        // USERNAME_CANONICALIZE("Bob_1")
        let mut req = 30u16.to_le_bytes().to_vec();
        req.extend(1u32.to_le_bytes());
        req.extend(5u32.to_le_bytes());
        req.extend(b"Bob_1");

        let mut out_len = 0usize;
        let ptr = unsafe { yap_call(req.as_ptr(), req.len(), &mut out_len) };
        let resp = unsafe { std::slice::from_raw_parts(ptr, out_len) }.to_vec();
        unsafe { yap_free(ptr, out_len) };

        assert_eq!(resp[0], 0);
        assert_eq!(&resp[resp.len() - 5..], b"bob_1");
    }

    #[test]
    fn empty_and_null_requests_are_errors_not_crashes() {
        let mut out_len = 0usize;
        let ptr = unsafe { yap_call(std::ptr::null(), 0, &mut out_len) };
        assert_eq!(unsafe { *ptr }, 1);
        unsafe { yap_free(ptr, out_len) };
        unsafe { yap_free(std::ptr::null_mut(), 0) };
    }
}
