//! Functions rust_witness normally implements as a NOP.

use std::ffi::{CStr, c_char, c_void};

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
extern "C" fn runtime__exceptionHandler(_arg: *const c_void) {
    eprintln!(
        "runtime__exceptionHandler called, don't know which circuit or how to parse the argument"
    );
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
extern "C" fn runtime__printErrorMessage(_arg: *const c_void) {
    eprintln!(
        "runtime__printErrorMessage called, don't know which circuit or how to parse the argument"
    );
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
extern "C" fn circuit_runtime__exceptionHandler(circuit_name: *const c_char, _arg: *const c_void) {
    // SAFETY: Our codegen always sets this to a const string.
    let circuit_name = unsafe { CStr::from_ptr(circuit_name) };
    let circuit_name = circuit_name.to_string_lossy();
    eprintln!("[{circuit_name}] exceptionHandler called")
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
extern "C" fn circuit_log_signal(
    circuit_name: *const c_char,
    _instance: *const c_void,
    len: u32,
    data: *const u32,
) {
    // SAFETY: Our codegen always sets this to a const string.
    let circuit_name = unsafe { CStr::from_ptr(circuit_name) };
    let circuit_name = circuit_name.to_string_lossy();
    // SAFETY: Our codegen always sets this to a pointer to the stack (even if len==0)
    let data = unsafe { std::slice::from_raw_parts(data, len as usize) };

    let value = num_bigint::BigUint::from_slice(data);

    eprintln!("[{circuit_name}] {value}");
}
// See https://github.com/iden3/snarkjs/blob/9a8f1c0083d18b9b5e18f526cfd729e7259423be/test/circuit2/circuit_js/witness_calculator.cjs#L44
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
extern "C" fn circuit_log_message(
    circuit_name: *const c_char,
    _instance: *const c_void,
    _typ: u32,
    message: *const c_char,
) {
    // SAFETY: Our codegen always sets this to a const string.
    let circuit_name = unsafe { CStr::from_ptr(circuit_name) };
    let circuit_name = circuit_name.to_string_lossy();
    // SAFETY: Our codegen always gives us a valid pointer to the stack, with 0 at the end.
    let message = unsafe { CStr::from_ptr(message) };
    let message = message.to_string_lossy();
    let message = message.strip_suffix('\n').unwrap_or(&message);
    if !message.is_empty() {
        eprintln!("[{circuit_name}] {message}");
    }
}
