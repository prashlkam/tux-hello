//! Real security keys through libfido2 (hand-written bindings for the ~35
//! functions we use; values from <fido.h> 1.13+).
//!
//! All calls block. They run on tokio's blocking pool, and the async side
//! cancels them through [`CancelToken`], which calls `fido_dev_cancel` from
//! another thread, as libfido2 documents.

use std::ffi::{c_char, c_int, c_uchar, CStr, CString};
use std::ptr;
use std::sync::Once;

use super::{
    Assertion, Authenticator, CancelToken, DeviceInfo, GetAssertion, KeyError, MakeCredential,
    NewCredential, COSE_ES256,
};

#[repr(C)]
struct FidoDev {
    _p: [u8; 0],
}
#[repr(C)]
struct FidoDevInfo {
    _p: [u8; 0],
}
#[repr(C)]
struct FidoCred {
    _p: [u8; 0],
}
#[repr(C)]
struct FidoAssert {
    _p: [u8; 0],
}

const FIDO_OK: c_int = 0;
const FIDO_OPT_OMIT: c_int = 0;
const FIDO_OPT_TRUE: c_int = 2;

const FIDO_ERR_KEEPALIVE_CANCEL: c_int = 0x2d;
const FIDO_ERR_NO_CREDENTIALS: c_int = 0x2e;
const FIDO_ERR_USER_ACTION_TIMEOUT: c_int = 0x2f;
const FIDO_ERR_PIN_INVALID: c_int = 0x31;
const FIDO_ERR_PIN_BLOCKED: c_int = 0x32;
const FIDO_ERR_PIN_AUTH_BLOCKED: c_int = 0x34;
const FIDO_ERR_PIN_REQUIRED: c_int = 0x36;
const FIDO_ERR_ACTION_TIMEOUT: c_int = 0x3a;
const FIDO_ERR_UV_BLOCKED: c_int = 0x3c;
const FIDO_ERR_UV_INVALID: c_int = 0x3f;

const MAX_DEVICES: usize = 16;

#[link(name = "fido2")]
extern "C" {
    fn fido_init(flags: c_int);
    fn fido_strerr(err: c_int) -> *const c_char;

    fn fido_dev_info_new(n: usize) -> *mut FidoDevInfo;
    fn fido_dev_info_free(di: *mut *mut FidoDevInfo, n: usize);
    fn fido_dev_info_manifest(di: *mut FidoDevInfo, ilen: usize, olen: *mut usize) -> c_int;
    fn fido_dev_info_ptr(di: *const FidoDevInfo, i: usize) -> *const FidoDevInfo;
    fn fido_dev_info_path(di: *const FidoDevInfo) -> *const c_char;
    fn fido_dev_info_product_string(di: *const FidoDevInfo) -> *const c_char;
    fn fido_dev_info_manufacturer_string(di: *const FidoDevInfo) -> *const c_char;

    fn fido_dev_new() -> *mut FidoDev;
    fn fido_dev_free(dev: *mut *mut FidoDev);
    fn fido_dev_open(dev: *mut FidoDev, path: *const c_char) -> c_int;
    fn fido_dev_close(dev: *mut FidoDev) -> c_int;
    fn fido_dev_cancel(dev: *mut FidoDev) -> c_int;
    fn fido_dev_make_cred(dev: *mut FidoDev, cred: *mut FidoCred, pin: *const c_char) -> c_int;
    fn fido_dev_get_assert(dev: *mut FidoDev, a: *mut FidoAssert, pin: *const c_char) -> c_int;

    fn fido_cred_new() -> *mut FidoCred;
    fn fido_cred_free(cred: *mut *mut FidoCred);
    fn fido_cred_set_type(cred: *mut FidoCred, cose_alg: c_int) -> c_int;
    fn fido_cred_set_clientdata_hash(cred: *mut FidoCred, p: *const c_uchar, len: usize) -> c_int;
    fn fido_cred_set_rp(cred: *mut FidoCred, id: *const c_char, name: *const c_char) -> c_int;
    fn fido_cred_set_user(
        cred: *mut FidoCred,
        user_id: *const c_uchar,
        len: usize,
        name: *const c_char,
        display_name: *const c_char,
        icon: *const c_char,
    ) -> c_int;
    fn fido_cred_set_uv(cred: *mut FidoCred, opt: c_int) -> c_int;
    fn fido_cred_set_rk(cred: *mut FidoCred, opt: c_int) -> c_int;
    fn fido_cred_id_ptr(cred: *const FidoCred) -> *const c_uchar;
    fn fido_cred_id_len(cred: *const FidoCred) -> usize;
    fn fido_cred_pubkey_ptr(cred: *const FidoCred) -> *const c_uchar;
    fn fido_cred_pubkey_len(cred: *const FidoCred) -> usize;

    fn fido_assert_new() -> *mut FidoAssert;
    fn fido_assert_free(a: *mut *mut FidoAssert);
    fn fido_assert_set_clientdata_hash(a: *mut FidoAssert, p: *const c_uchar, len: usize) -> c_int;
    fn fido_assert_set_rp(a: *mut FidoAssert, id: *const c_char) -> c_int;
    fn fido_assert_allow_cred(a: *mut FidoAssert, p: *const c_uchar, len: usize) -> c_int;
    fn fido_assert_set_up(a: *mut FidoAssert, opt: c_int) -> c_int;
    fn fido_assert_set_uv(a: *mut FidoAssert, opt: c_int) -> c_int;
    fn fido_assert_count(a: *const FidoAssert) -> usize;
    fn fido_assert_id_ptr(a: *const FidoAssert, idx: usize) -> *const c_uchar;
    fn fido_assert_id_len(a: *const FidoAssert, idx: usize) -> usize;
    fn fido_assert_authdata_raw_ptr(a: *const FidoAssert, idx: usize) -> *const c_uchar;
    fn fido_assert_authdata_raw_len(a: *const FidoAssert, idx: usize) -> usize;
    fn fido_assert_sig_ptr(a: *const FidoAssert, idx: usize) -> *const c_uchar;
    fn fido_assert_sig_len(a: *const FidoAssert, idx: usize) -> usize;
}

fn strerr(rc: c_int) -> String {
    // SAFETY: fido_strerr returns a static string for any value.
    unsafe { CStr::from_ptr(fido_strerr(rc)) }
        .to_string_lossy()
        .into_owned()
}

fn map_err(rc: c_int) -> KeyError {
    match rc {
        FIDO_ERR_NO_CREDENTIALS => KeyError::NoCredentials,
        FIDO_ERR_PIN_REQUIRED => KeyError::PinRequired,
        FIDO_ERR_PIN_INVALID | FIDO_ERR_UV_INVALID => KeyError::PinInvalid,
        FIDO_ERR_PIN_BLOCKED | FIDO_ERR_PIN_AUTH_BLOCKED | FIDO_ERR_UV_BLOCKED => KeyError::Blocked,
        FIDO_ERR_ACTION_TIMEOUT | FIDO_ERR_USER_ACTION_TIMEOUT => KeyError::Timeout,
        FIDO_ERR_KEEPALIVE_CANCEL => KeyError::Cancelled,
        other => KeyError::Other(format!("libfido2: {} ({other})", strerr(other))),
    }
}

fn check(rc: c_int) -> Result<(), KeyError> {
    if rc == FIDO_OK {
        Ok(())
    } else {
        Err(map_err(rc))
    }
}

fn cstr(s: &str) -> Result<CString, KeyError> {
    CString::new(s).map_err(|_| KeyError::Other("string contains NUL".into()))
}

/// SAFETY: `p` must be NULL or point to `len` readable bytes.
unsafe fn bytes(p: *const c_uchar, len: usize) -> Vec<u8> {
    if p.is_null() || len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(p, len).to_vec()
    }
}

/// Raw device pointer that may be handed to the cancel hook on another thread.
struct DevPtr(*mut FidoDev);
// SAFETY: libfido2 allows fido_dev_cancel() from another thread while the
// owning thread is blocked in a device call; the hook is removed (under the
// CancelToken mutex) before the device is closed and freed.
unsafe impl Send for DevPtr {}

/// An open device, closed and freed on drop.
struct Device {
    dev: *mut FidoDev,
}

impl Device {
    fn open(path: &str) -> Result<Self, KeyError> {
        let p = cstr(path)?;
        // SAFETY: plain constructor; checked for NULL.
        let dev = unsafe { fido_dev_new() };
        if dev.is_null() {
            return Err(KeyError::Other("fido_dev_new failed".into()));
        }
        let mut d = Device { dev };
        // SAFETY: valid device and C string.
        let rc = unsafe { fido_dev_open(d.dev, p.as_ptr()) };
        if rc != FIDO_OK {
            // Not opened: free without close.
            // SAFETY: frees the device allocated above.
            unsafe { fido_dev_free(&mut d.dev) };
            d.dev = ptr::null_mut();
            return Err(map_err(rc));
        }
        Ok(d)
    }

    /// Runs `f` with the device, making `cancel` able to interrupt it.
    fn with_cancel<T>(
        &self,
        cancel: &CancelToken,
        f: impl FnOnce(*mut FidoDev) -> Result<T, KeyError>,
    ) -> Result<T, KeyError> {
        let dp = DevPtr(self.dev);
        let armed = cancel.set_hook(Box::new(move || {
            let dp = &dp;
            // SAFETY: see DevPtr.
            unsafe { fido_dev_cancel(dp.0) };
        }));
        let r = if armed {
            f(self.dev)
        } else {
            Err(KeyError::Cancelled)
        };
        cancel.clear_hook();
        r
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if !self.dev.is_null() {
            // SAFETY: opened in `open`; freed exactly once.
            unsafe {
                fido_dev_close(self.dev);
                fido_dev_free(&mut self.dev);
            }
        }
    }
}

/// libfido2-backed [`Authenticator`].
pub struct LibFido2;

impl LibFido2 {
    pub fn new() -> Self {
        static INIT: Once = Once::new();
        // SAFETY: library initialisation, once per process.
        INIT.call_once(|| unsafe { fido_init(0) });
        LibFido2
    }
}

impl Authenticator for LibFido2 {
    fn devices(&self) -> Vec<DeviceInfo> {
        // SAFETY: allocate, fill, read, free a device-info array of
        // MAX_DEVICES entries; we only read the first `n` filled ones.
        unsafe {
            let mut list = fido_dev_info_new(MAX_DEVICES);
            if list.is_null() {
                return Vec::new();
            }
            let mut n: usize = 0;
            let mut out = Vec::new();
            if fido_dev_info_manifest(list, MAX_DEVICES, &mut n) == FIDO_OK {
                for i in 0..n.min(MAX_DEVICES) {
                    let di = fido_dev_info_ptr(list, i);
                    let s = |p: *const c_char| {
                        if p.is_null() {
                            String::new()
                        } else {
                            CStr::from_ptr(p).to_string_lossy().into_owned()
                        }
                    };
                    let path = s(fido_dev_info_path(di));
                    if path.is_empty() {
                        continue;
                    }
                    let product = format!(
                        "{} {}",
                        s(fido_dev_info_manufacturer_string(di)),
                        s(fido_dev_info_product_string(di))
                    )
                    .trim()
                    .to_string();
                    out.push(DeviceInfo { path, product });
                }
            }
            fido_dev_info_free(&mut list, MAX_DEVICES);
            out
        }
    }

    fn make_credential(
        &self,
        dev: &DeviceInfo,
        req: &MakeCredential<'_>,
        pin: Option<&str>,
        cancel: &CancelToken,
    ) -> Result<NewCredential, KeyError> {
        let device = Device::open(&dev.path)?;
        let rp = cstr(req.rp_id)?;
        let name = cstr(req.user_name)?;
        let pin_c = pin.map(cstr).transpose()?;
        // SAFETY: the credential is allocated, used and freed in this block;
        // all pointers passed are valid for the duration of each call.
        unsafe {
            let mut cred = fido_cred_new();
            if cred.is_null() {
                return Err(KeyError::Other("fido_cred_new failed".into()));
            }
            let r = (|| {
                check(fido_cred_set_type(cred, COSE_ES256))?;
                check(fido_cred_set_clientdata_hash(
                    cred,
                    req.client_data_hash.as_ptr(),
                    req.client_data_hash.len(),
                ))?;
                check(fido_cred_set_rp(cred, rp.as_ptr(), rp.as_ptr()))?;
                check(fido_cred_set_user(
                    cred,
                    req.user_id.as_ptr(),
                    req.user_id.len(),
                    name.as_ptr(),
                    name.as_ptr(),
                    ptr::null(),
                ))?;
                // Non-resident credential: nothing is stored on the key.
                check(fido_cred_set_rk(cred, FIDO_OPT_OMIT))?;
                if req.uv {
                    check(fido_cred_set_uv(cred, FIDO_OPT_TRUE))?;
                }
                let pin_ptr = pin_c.as_ref().map_or(ptr::null(), |p| p.as_ptr());
                device.with_cancel(cancel, |d| check(fido_dev_make_cred(d, cred, pin_ptr)))?;
                let id = bytes(fido_cred_id_ptr(cred), fido_cred_id_len(cred));
                let public_key = bytes(fido_cred_pubkey_ptr(cred), fido_cred_pubkey_len(cred));
                if id.is_empty() || public_key.is_empty() {
                    return Err(KeyError::Other("key returned an empty credential".into()));
                }
                Ok(NewCredential {
                    id,
                    alg: COSE_ES256,
                    public_key,
                })
            })();
            fido_cred_free(&mut cred);
            r
        }
    }

    fn get_assertion(
        &self,
        dev: &DeviceInfo,
        req: &GetAssertion<'_>,
        pin: Option<&str>,
        cancel: &CancelToken,
    ) -> Result<Assertion, KeyError> {
        let device = Device::open(&dev.path)?;
        let rp = cstr(req.rp_id)?;
        let pin_c = pin.map(cstr).transpose()?;
        // SAFETY: as in make_credential.
        unsafe {
            let mut a = fido_assert_new();
            if a.is_null() {
                return Err(KeyError::Other("fido_assert_new failed".into()));
            }
            let r = (|| {
                check(fido_assert_set_clientdata_hash(
                    a,
                    req.client_data_hash.as_ptr(),
                    req.client_data_hash.len(),
                ))?;
                check(fido_assert_set_rp(a, rp.as_ptr()))?;
                for id in req.allow {
                    check(fido_assert_allow_cred(a, id.as_ptr(), id.len()))?;
                }
                check(fido_assert_set_up(a, FIDO_OPT_TRUE))?;
                if req.uv {
                    check(fido_assert_set_uv(a, FIDO_OPT_TRUE))?;
                }
                let pin_ptr = pin_c.as_ref().map_or(ptr::null(), |p| p.as_ptr());
                device.with_cancel(cancel, |d| check(fido_dev_get_assert(d, a, pin_ptr)))?;
                if fido_assert_count(a) < 1 {
                    return Err(KeyError::Other("key returned no assertion".into()));
                }
                Ok(Assertion {
                    credential_id: bytes(fido_assert_id_ptr(a, 0), fido_assert_id_len(a, 0)),
                    auth_data: bytes(
                        fido_assert_authdata_raw_ptr(a, 0),
                        fido_assert_authdata_raw_len(a, 0),
                    ),
                    signature: bytes(fido_assert_sig_ptr(a, 0), fido_assert_sig_len(a, 0)),
                })
            })();
            fido_assert_free(&mut a);
            r
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_mapping() {
        assert_eq!(map_err(FIDO_ERR_NO_CREDENTIALS), KeyError::NoCredentials);
        assert_eq!(map_err(FIDO_ERR_PIN_REQUIRED), KeyError::PinRequired);
        assert_eq!(map_err(FIDO_ERR_PIN_INVALID), KeyError::PinInvalid);
        assert_eq!(map_err(FIDO_ERR_KEEPALIVE_CANCEL), KeyError::Cancelled);
        assert_eq!(map_err(FIDO_ERR_ACTION_TIMEOUT), KeyError::Timeout);
        assert!(matches!(map_err(-7), KeyError::Other(m) if m.contains("libfido2")));
    }

    #[test]
    fn enumerating_devices_does_not_crash() {
        // No key is attached in CI; this exercises the FFI round trip.
        let _ = LibFido2::new().devices();
    }
}
