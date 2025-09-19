use anyhow::{Context, Result};
use std::{
    ffi::CStr,
    fs::OpenOptions,
    io::Write,
    os::raw::{c_char, c_int},
};

// PAM constants
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_OPEN_ERR: c_int = 1;
pub const PAM_SYMBOL_ERR: c_int = 2;
pub const PAM_SERVICE_ERR: c_int = 3;
pub const PAM_SYSTEM_ERR: c_int = 4;
pub const PAM_BUF_ERR: c_int = 5;
pub const PAM_PERM_DENIED: c_int = 6;
pub const PAM_AUTH_ERR: c_int = 7;
pub const PAM_CRED_INSUFFICIENT: c_int = 8;
pub const PAM_AUTHINFO_UNAVAIL: c_int = 9;
pub const PAM_USER_UNKNOWN: c_int = 10;
pub const PAM_MAXTRIES: c_int = 11;
pub const PAM_NEW_AUTHTOK_REQD: c_int = 12;
pub const PAM_ACCT_EXPIRED: c_int = 13;
pub const PAM_SESSION_ERR: c_int = 14;
pub const PAM_CRED_UNAVAIL: c_int = 15;
pub const PAM_CRED_EXPIRED: c_int = 16;
pub const PAM_CRED_ERR: c_int = 17;
pub const PAM_NO_MODULE_DATA: c_int = 18;
pub const PAM_CONV_ERR: c_int = 19;
pub const PAM_AUTHTOK_ERR: c_int = 20;
pub const PAM_AUTHTOK_RECOVER_ERR: c_int = 21;
pub const PAM_AUTHTOK_LOCK_BUSY: c_int = 22;
pub const PAM_AUTHTOK_DISABLE_AGING: c_int = 23;
pub const PAM_TRY_AGAIN: c_int = 24;
pub const PAM_IGNORE: c_int = 25;
pub const PAM_ABORT: c_int = 26;
pub const PAM_AUTHTOK_EXPIRED: c_int = 27;
pub const PAM_MODULE_UNKNOWN: c_int = 28;
pub const PAM_BAD_ITEM: c_int = 29;
pub const PAM_CONV_AGAIN: c_int = 30;
pub const PAM_INCOMPLETE: c_int = 31;

// PAM flag constants
pub const PAM_SILENT: c_int = 0x8000;
pub const PAM_DISALLOW_NULL_AUTHTOK: c_int = 0x0001;
pub const PAM_ESTABLISH_CRED: c_int = 0x0002;
pub const PAM_DELETE_CRED: c_int = 0x0004;
pub const PAM_REINITIALIZE_CRED: c_int = 0x0008;
pub const PAM_REFRESH_CRED: c_int = 0x0010;
pub const PAM_CHANGE_EXPIRED_AUTHTOK: c_int = 0x0020;

// Opaque PAM handle type
#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

// PAM session management functions
/// # Safety
/// This function is called by the PAM framework and expects valid pointers for all arguments.
/// The caller must ensure that `pamh` and `argv` are valid for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_open_session(
    _pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let mut score = 0;

    // Properly handle null argv
    if argc > 0 && !argv.is_null() {
        unsafe {
            let first_arg_ptr = *argv.offset(0);
            if !first_arg_ptr.is_null() {
                if let Ok(arg_str) = CStr::from_ptr(first_arg_ptr).to_str() {
                    if let Ok(num) = arg_str.parse::<i32>() {
                        score = num;
                    }
                }
            }
        }
    }

    if !(-1000..=1000).contains(&score) {
        score = 0;
    }

    match set_oom_adj_score(score) {
        Ok(_) => PAM_SUCCESS,
        Err(msg) => {
            println!("PAM_SSHD_OOM: Failed to adjust user OOM Adjust Score.");
            println!("PAM_SSHD_OOM: {msg}");
            PAM_IGNORE
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_acct_mgmt(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SERVICE_ERR
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    PAM_SERVICE_ERR
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_chauthtok(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SERVICE_ERR
}

fn set_oom_adj_score(score: i32) -> Result<c_int> {
    let mut file = OpenOptions::new()
        .write(true)
        .open("/proc/self/oom_score_adj")
        .context("Failed to open /proc/self/oom_score_adj.")?;
    file.write_all(score.to_string().as_bytes()).map_err(|e| {
        anyhow::anyhow!(
            "Failed to write OOM Adjust score {score} to /proc/self/oom_score_adj: {}",
            e
        )
    })?;

    Ok(PAM_SUCCESS)
}
