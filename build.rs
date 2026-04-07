// use std::{
//     env,
//     fs::create_dir,
//     io::{BufRead, ErrorKind},
//     path::PathBuf,
//     process::Command,
//     str::FromStr,
// };

fn main() {
    // let out_dir = env::var("OUT_DIR").unwrap();
    // let circom_output = PathBuf::from_str(&out_dir).unwrap().join("circom");
    // let circom_output = circom_output.to_str().unwrap();
    //
    // match create_dir(circom_output) {
    //     Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
    //     e => e.unwrap(),
    // }

    // Recompile if anything in the circuits directory changed.
    // println!("cargo::rerun-if-changed=circuits");

    // I've disabled automatic recompilation because I'm currently writing the zkey and
    // transpile_wasm only cares about the wasm files.
    // println!("cargo::rerun-if-changed=zkey/sdjwt_es256_2sha256_1claim_js");

    // Run circom
    // compile_circom("dlpexample", circom_output);

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let zkey_dir = std::path::Path::new(&manifest_dir).join("zkey");

    // println!("cargo::rustc-link-lib=stdbool");

    // transpile_wasm adds a cargo directive that causes recompilation when files in circom_output
    // change. Since we are creating these files this means the crate will always be considered
    // ddirty. Luckily it is the first line emitted, so we can add a prefix to disable it.
    // print!("IGNORED CARGO DIRECTIVE: ");

    // Searches the directory recursively for wasm files.
    // Why does everyone want owned strings for no reason?
    // transpile_wasm(circom_output.to_owned());
    rust_witness2::transpile_wasm(zkey_dir.to_string_lossy().to_string());
}

// fn compile_circom(name: &str, circom_output: &str) {
//     eprintln!("Compiling Circuit \"{name}.circom\"");
//     cmd_print_on_err(
//         "circom",
//         &[
//             &format!("circuits/{name}.circom"),
//             "-p", // Curve selection
//             "bls12381",
//             "--r1cs",
//             "--wasm",
//             "-o",
//             circom_output,
//             "-l",
//             "circuits",
//         ],
//     );
// }

// fn cmd_print_on_err(cmd: &str, args: &[&str]) {
//     // Run the command and capture stdout and stderr
//     let output = Command::new(cmd)
//         .args(args)
//         .output()
//         .expect(&format!("Failed to execute {cmd}"));
//
//     // Print stdout and stderr with a prefix to avoid `cargo:` injections.
//     for line in output.stdout.lines() {
//         let line = line.expect("Reading captured output shouldn't fail");
//         eprintln!("circom.stdout: {}", line);
//     }
//     for line in output.stderr.lines() {
//         let line = line.expect("Reading captured output shouldn't fail");
//         eprintln!("circom.stderr: {}", line);
//     }
//
//     // Fail compilation if circom did not compile successfully
//     if !output.status.success() {
//         panic!("circom execuion failed with status {}", output.status)
//     }
// }

mod rust_witness2 {
    //! A few modifications to rust_witness::transpile_wasm, to improve error handling and fix
    //! issues I've ran into. I've split it up into multiple functions to allow more flexibility.

    use std::{
        env,
        ffi::OsStr,
        fs,
        path::{Path, PathBuf},
        process::Command,
    };

    use walkdir::WalkDir;

    // Mostly the same as the original, changes have been marked with // CHANGED:
    pub fn transpile_wasm(wasmdir: String) {
        if !Path::is_dir(Path::new(wasmdir.as_str())) {
            panic!("wasmdir must be a directory");
        }
        println!("cargo:rerun-if-changed={}", wasmdir);

        let (w2c2, w2c2_path) = w2c2_cmd();

        let circuit_out_dir = env::var("OUT_DIR").unwrap();
        let mut builder = cc::Build::new();
        // empty the handlers file
        let mut handler = "".to_string();
        // CHANGED: Removed globals_c. Implementing them manually in Rust allows more flexibility.
        // CHANGED: Added c99 flag (I had issues compiling without it).
        builder
            // .file(globals_c_path.to_str().unwrap())
            .file(
                Path::new(circuit_out_dir.as_str())
                    .join(Path::new("handlers.c"))
                    .to_str()
                    .unwrap(),
            )
            .flag(format!("-I{}", w2c2_path.join("w2c2").to_str().unwrap()).as_str())
            .flag("-std=c99")
            .flag("-Wno-unused-label")
            .flag("-Wno-unused-but-set-variable")
            .flag("-Wno-unused-variable")
            .flag("-Wno-unused-parameter")
            .flag("-Wno-null-character")
            .flag("-Wno-c2x-extensions");

        // CHANGED: This used to be in globals.c, I've moved it to this file because I had to
        // change some of it anyways:
        // - Removed `void runtime__exceptionHandler(void*) {}`
        // - Removed `void runtime__printErrorMessage(void*) {}`
        // - Added forward declarations for two functions inmplemented in Rust:
        handler.push_str(
            r#"
#include <stdio.h>
#include "w2c2_base.h"

// To be implemented in Rust
void runtime__exceptionHandler(void* arg);
void runtime__printErrorMessage(void* arg);
void circuit_runtime__exceptionHandler(char* circuit_name, void* arg);
void circuit_log_signal(char* circuit_name, void* instance, unsigned int len, unsigned int *data);
void circuit_log_message(char* circuit_name, void* instance, int type, char* message);

void trap(Trap trap) {
    fprintf(stderr, "TRAP: %s\n", trapDescription(trap));
    abort();
}

typedef struct instance { wasmModuleInstance common;
    wasmMemory* m0;
    wasmTable t0;
} instance;

instance* witness_c_init() {
    instance* i = malloc(sizeof(struct instance));
    return i;
}

typedef void* (_resolver)(const char*, const char*);

_resolver* witness_c_resolver() {
    return NULL;
}

void witness_c_cleanup(instance * i) {
    free(i);
}
        "#,
        );

        let mut last_modified_file = std::time::SystemTime::UNIX_EPOCH;
        for entry in WalkDir::new(wasmdir) {
            let e = entry.unwrap();
            let path = e.path();
            if path.is_dir() {
                continue;
            }
            let ext = path.extension().and_then(OsStr::to_str).unwrap_or("");
            // Iterate over all wasm files and generate c source, then compile each source to
            // a static library that can be called from rust
            if ext != "wasm" {
                continue;
            }
            // make source files with the same name as the wasm binary file
            let circuit_name = path.file_stem().unwrap();
            let circuit_name_compressed = circuit_name
                .to_str()
                .unwrap()
                .replace("_", "")
                .replace("-", "");
            // CHANGED: Added variable with the original circuit name.
            let circuit_name_str = circuit_name.to_str().unwrap();
            // CHANGED: Combined into a single push_str.
            // CHANGED: Added forwarding to custom functions implemented in Rust.
            // CHANGED: Added forwarding to custom functions implemented in Rust.
            // NOTE: snarkjs concats the messages into a single string and outputs on newline. For
            //       simplicity we're just outputting immediately. Otherwise we'd need a static
            //       lookup based on &instance.
            handler.push_str(&format!(
                r#"
                int {circuit_name_compressed}_getMessageChar(void* i);
                int {circuit_name_compressed}_getFieldNumLen32(void* i);
                int {circuit_name_compressed}_readSharedRWMemory(void *i, unsigned int addr);

                void {circuit_name_compressed}_runtime__exceptionHandler(void* arg) {{
                    circuit_runtime__exceptionHandler("{circuit_name_str}", arg);
                }}
                void {circuit_name_compressed}_runtime__printErrorMessage(void* instance) {{
                    // Get the message (for simplicity truncate long messages)
                    char message[1024];
                    int i = 0;
                    char c;
                    do {{
                        c = {circuit_name_compressed}_getMessageChar(instance);
                        message[i] = c;
                        i++;
                    }} while (c != 0 && i < 1024);
                    
                    // Make truncate if necessary.
                    message[1023] = 0;

                    // Call the Rust handler
                    circuit_log_message("{circuit_name_str}", instance, 1, message);
                }}
                // See https://github.com/iden3/snarkjs/blob/9a8f1c0083d18b9b5e18f526cfd729e7259423be/test/circuit2/circuit_js/witness_calculator.cjs#L91
                void {circuit_name_compressed}_runtime__showSharedRWMemory(void *instance) {{
                    unsigned int len = {circuit_name_compressed}_getFieldNumLen32(instance);

                    // Get the data (for simplicity I'm assuming its just one signal, snarkjs also
                    // only outputs a single number). Allow up to u256
                    unsigned int data[8];
                    if (len > 8) {{
                        len = 8;
                    }}

                    // Read the data
                    for (unsigned int i = 0; i < len; i++) {{
                        data[i] = {circuit_name_compressed}_readSharedRWMemory(instance, i);
                    }}

                    // Give the array to Rust, probably easier than building the number here.
                    circuit_log_signal("{circuit_name_str}", instance, len, data);
                }}
                // See https://github.com/iden3/snarkjs/blob/9a8f1c0083d18b9b5e18f526cfd729e7259423be/test/circuit2/circuit_js/witness_calculator.cjs#L81
                void {circuit_name_compressed}_runtime__writeBufferMessage(void *instance) {{
                    // Get the message (for simplicity truncate long messages)
                    char message[1024];
                    int i = 0;
                    char c;
                    do {{
                        c = {circuit_name_compressed}_getMessageChar(instance);
                        message[i] = c;
                        i++;
                    }} while (c != 0 && i < 1024);
                    
                    // Make truncate if necessary.
                    message[1023] = 0;

                    // Call the Rust handler
                    circuit_log_message("{circuit_name_str}", instance, 0, message);
                }}
                "#,
            ));

            // w2c2 is using a fixed naming convention when splitting source by the number of functions ("-f n" flag).
            // The output files are named s00..01.c, s00..02.c, s00..03.c, etc., and a main file named after the wasm file.
            // As there may be multiple wasm files, we need to transpile each wasm file into a separate directory to prevent
            // w2c2 from overwriting the s..x.c files.

            let circuit_out_dir =
                Path::new(&circuit_out_dir).join(Path::new(circuit_name.to_str().unwrap()));

            if !circuit_out_dir.exists() {
                fs::create_dir(&circuit_out_dir)
                    .expect("Failed to create circuit output directory");
            }

            let out = Path::new(&circuit_out_dir)
                .join(Path::new(path.file_name().unwrap()))
                .with_extension("c");
            // Check if the source file needs to be regenerated
            if needs_regeneration(path, &out) {
                // first generate the c source
                w2c2()
                    .arg("-p")
                    .arg("-m")
                    .arg("-f")
                    .arg("1")
                    .arg(path)
                    .arg(out.clone())
                    .spawn()
                    .expect("Failed to spawn w2c2")
                    .wait()
                    .expect("w2c2 command errored");

                let contents = fs::read_to_string(out.clone()).unwrap();
                // make the data constants static to prevent duplicate symbol errors
                fs::write(
                    out.clone(),
                    contents.replace("const U8 d", "static const U8 d"),
                )
                .expect("Error modifying data symbols");
            } else {
                println!(
                    "C source files are up to date, skipping transpilation: {}",
                    path.display()
                );
                last_modified_file = std::cmp::max(
                    last_modified_file,
                    fs::metadata(&out)
                        .expect("Failed to read metadata")
                        .modified()
                        .expect("Failed to read modified time"),
                );
            }

            builder.file(out.clone());
            // Add all the files to the builder that start with "s0..." and end with ".c" (the results of w2c2 `-f` flag)
            for entry in WalkDir::new(circuit_out_dir.clone()) {
                let e = entry.unwrap();
                let path = e.path();
                if path.is_dir() {
                    continue;
                }
                let ext = path.extension().and_then(OsStr::to_str).unwrap_or("");
                if ext != "c" {
                    continue;
                }
                if path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("s0")
                    && path.file_name().unwrap().to_str().unwrap().ends_with(".c")
                {
                    builder.file(path);
                }
            }
        }

        let handlers = Path::new(circuit_out_dir.as_str()).join("handlers.c");
        fs::write(handlers, handler).expect("Error writing handler source");

        builder.compile("circuit");
    }

    const W2C2_BUILD_SCRIPT: &str = include_str!("scripts/build_w2c2.sh");

    /// Get a function to spawn w2c2, either from $PATH or by building locally
    // NOTE: Copied without changes
    fn w2c2_cmd() -> (fn() -> Command, PathBuf) {
        let w2c2_path = Path::new(env::var("OUT_DIR").unwrap().as_str()).join(Path::new("w2c2"));
        let w2c2_script_path =
            Path::new(env::var("OUT_DIR").unwrap().as_str()).join(Path::new("build_w2c2.sh"));
        fs::write(&w2c2_script_path, W2C2_BUILD_SCRIPT).expect("Failed to write build script");
        match Command::new("w2c2").spawn() {
            Ok(_) => {
                // clone the repo to get the headers
                Command::new("sh")
                    .arg(w2c2_script_path.to_str().unwrap())
                    .arg("1")
                    .spawn()
                    .expect("Failed to spawn w2c2 build")
                    .wait()
                    .expect("w2c2 build errored");
                // Run the binary in the PATH
                (|| Command::new("w2c2"), w2c2_path)
            }
            Err(_e) => {
                // Build the w2c2 binary
                Command::new("sh")
                    .arg(w2c2_script_path.to_str().unwrap())
                    .spawn()
                    .expect("Failed to spawn w2c2 build")
                    .wait()
                    .expect("w2c2 build errored");
                (
                    || {
                        let w2c2_path = Path::new(env::var("OUT_DIR").unwrap().as_str())
                            .join(Path::new("w2c2"));
                        let w2c2_exec_path = w2c2_path.join(Path::new("build/w2c2/w2c2"));
                        Command::new(w2c2_exec_path.to_str().unwrap())
                    },
                    w2c2_path,
                )
            }
        }
    }

    // NOTE: Copied without changes
    fn needs_regeneration(source: &Path, generated: &Path) -> bool {
        if !generated.exists() {
            return true;
        }
        let source_metadata = fs::metadata(source).expect("Failed to read source metadata");
        let generated_metadata =
            fs::metadata(generated).expect("Failed to read generated metadata");

        let source_modified = source_metadata
            .modified()
            .expect("Failed to read source modification time");
        let generated_modified = generated_metadata
            .modified()
            .expect("Failed to read generated modification time");

        source_modified > generated_modified
    }
}
