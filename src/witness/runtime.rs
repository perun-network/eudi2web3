//! Functions rust_witness normally implements as a NOP.

use std::{
    ffi::{CStr, c_char, c_void},
    ptr::null_mut,
};

#[unsafe(no_mangle)]
extern "C" fn trap(trap: i32) -> ! {
    // Trap is a typedef enum defined in w2c2_base.h
    let description = match trap {
        0 => "unreachable",
        1 => "divide by zero",
        2 => "int overflow",
        3 => "invalid conversion",
        4 => "allocation failed",
        _ => "unknown",
    };
    eprintln!("trap called: {description}, don't know which circuit");
    // We MUST NOT panic and let the panic propagate through C, that is UB.
    // We also must not return back into C from this function, that is also UB.
    // Thus our only options are:
    // - abort and kill the process
    // - Jump back directly into the code that called the C code (via thread-local) and cleanup the
    //   stack. I'm not sure if this is problematic or UB (my gut says no).
    std::process::abort()
}

// No idea why this exists, the rust_witness macro expects it but I couldn't find it in any of the
// generated code.
#[unsafe(no_mangle)]
extern "C" fn witness_c_resolver() -> *const c_void {
    std::ptr::null()
}
#[unsafe(no_mangle)]
extern "C" fn witness_c_init() -> *mut Instance {
    let layout = std::alloc::Layout::new::<Instance>();
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) } as *mut Instance;
    if ptr.is_null() {
        return null_mut();
    }
    ptr
}
#[unsafe(no_mangle)]
extern "C" fn witness_c_cleanup(ptr: *mut Instance) {
    if ptr.is_null() {
        return;
    }
    let layout = std::alloc::Layout::new::<Instance>();
    unsafe { std::alloc::dealloc(ptr as *mut u8, layout) };
}

// This could be problematic if w2c2 ever changes this layout. To avoid that we'd need to compile a
// tiny C code for getting the size or allocating this. For now we'll assume it doesn't change.
// Problem is that this could result in UB if the size increases in the future without us updating
// this.
//
// NOTE: Technically we could read directly from this instead of jumping through generated C
// functions.
//
// typedef struct instance { wasmModuleInstance common;
//     wasmMemory* m0;
//     wasmTable t0;
// } instance;
#[repr(C)]
struct Instance {
    common: WasmModuleInstance,
    m0: *const c_void,
    t0: WasmTable,
}
// typedef struct wasmModuleInstance {
//     wasmFuncExport* funcExports;
//     void* (*resolveImports)(const char* module, const char* name);
//     struct wasmModuleInstance* (*newChild)(struct wasmModuleInstance* self);
// } wasmModuleInstance;
#[repr(C)]
struct WasmModuleInstance {
    func_exports: *const c_void,
    resolve_imports: Option<unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void>,
    new_child: Option<unsafe extern "C" fn(*mut WasmModuleInstance) -> *mut WasmModuleInstance>,
}
// typedef void (*wasmFunc)(void);
type WasmFunc = Option<unsafe extern "C" fn()>;
// typedef struct wasmTable {
//     wasmFunc* data;
//     U32 size, maxSize;
// } wasmTable;
#[repr(C)]
struct WasmTable {
    data: *const WasmFunc,
    size: u32,
    max_size: u32,
}

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
