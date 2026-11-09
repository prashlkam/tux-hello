//! Minimal hand-written Linux-PAM bindings: only what the module uses.
//! Values come from <security/_pam_types.h>.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;

#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

pub const PAM_SUCCESS: c_int = 0;
pub const PAM_AUTH_ERR: c_int = 7;
pub const PAM_AUTHINFO_UNAVAIL: c_int = 9;
pub const PAM_IGNORE: c_int = 25;

pub const PAM_SILENT: c_int = 0x8000;

pub const PAM_SERVICE: c_int = 1;
pub const PAM_TTY: c_int = 3;
pub const PAM_RHOST: c_int = 4;

pub const PAM_TEXT_INFO: c_int = 4;

pub const LOG_ERR: c_int = 3;
pub const LOG_WARNING: c_int = 4;
pub const LOG_INFO: c_int = 6;
pub const LOG_DEBUG: c_int = 7;

#[link(name = "pam")]
extern "C" {
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char)
        -> c_int;
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_prompt(
        pamh: *mut PamHandle,
        style: c_int,
        response: *mut *mut c_char,
        fmt: *const c_char,
        ...
    ) -> c_int;
    fn pam_syslog(pamh: *const PamHandle, priority: c_int, fmt: *const c_char, ...);
}

/// Safe-ish wrapper around a PAM handle for the duration of one module call.
pub struct Pam {
    h: *mut PamHandle,
}

fn to_cstring(s: &str) -> CString {
    // Interior NULs can't be passed to C; drop them.
    CString::new(s.replace('\0', "")).unwrap_or_default()
}

impl Pam {
    /// # Safety
    /// `h` must be the valid handle PAM passed to the current `pam_sm_*` call.
    pub unsafe fn new(h: *mut PamHandle) -> Self {
        Pam { h }
    }

    /// Returns the target user, prompting for it if the application has not
    /// set it yet.
    pub fn user(&self) -> Option<String> {
        let mut p: *const c_char = ptr::null();
        // SAFETY: valid handle; PAM owns the returned string, which stays
        // valid until the next pam_set_item(PAM_USER); we copy it at once.
        let rc = unsafe { pam_get_user(self.h, &mut p, ptr::null()) };
        if rc != PAM_SUCCESS || p.is_null() {
            return None;
        }
        // SAFETY: non-null, NUL-terminated string owned by PAM.
        let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        (!s.is_empty()).then_some(s)
    }

    /// Returns a string item (PAM_SERVICE, PAM_TTY, PAM_RHOST, ...).
    pub fn item_str(&self, item: c_int) -> Option<String> {
        let mut p: *const c_void = ptr::null();
        // SAFETY: valid handle; string items are NUL-terminated C strings
        // owned by PAM; we copy immediately.
        let rc = unsafe { pam_get_item(self.h, item, &mut p) };
        if rc != PAM_SUCCESS || p.is_null() {
            return None;
        }
        let s = unsafe { CStr::from_ptr(p as *const c_char) }
            .to_string_lossy()
            .into_owned();
        Some(s)
    }

    /// Shows an informational message through the application's conversation
    /// function (e.g. "Looking for you…").
    pub fn info(&self, msg: &str) {
        let c = to_cstring(msg);
        // SAFETY: "%s" with one valid C string argument; response may be NULL
        // for PAM_TEXT_INFO (this is exactly what the pam_info() macro does).
        unsafe {
            pam_prompt(
                self.h,
                PAM_TEXT_INFO,
                ptr::null_mut(),
                c"%s".as_ptr(),
                c.as_ptr(),
            );
        }
    }

    /// Logs to syslog (authpriv) via pam_syslog.
    pub fn log(&self, priority: c_int, msg: &str) {
        let c = to_cstring(msg);
        // SAFETY: "%s" with one valid C string argument.
        unsafe { pam_syslog(self.h, priority, c"%s".as_ptr(), c.as_ptr()) };
    }
}

/// Collects `argc`/`argv` module arguments into Rust strings.
///
/// # Safety
/// `argv` must point to `argc` valid NUL-terminated strings (as passed by PAM).
pub unsafe fn args(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    if argv.is_null() || argc <= 0 {
        return Vec::new();
    }
    (0..argc as usize)
        .filter_map(|i| {
            let p = *argv.add(i);
            (!p.is_null()).then(|| CStr::from_ptr(p).to_string_lossy().into_owned())
        })
        .collect()
}
