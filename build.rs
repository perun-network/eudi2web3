// use std::{
//     env,
//     fs::create_dir,
//     io::{BufRead, ErrorKind},
//     path::PathBuf,
//     process::Command,
//     str::FromStr,
// };

use rust_witness::transpile::transpile_wasm;

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

    // Transpile circom wasm output to C and link it.
    // This env variable fixes a compilation error by disabling the w2c2 provided bool and using
    // the one from std. No idea why that's necessary.
    unsafe {
        std::env::set_var(
            "CFLAGS", // "-include stdbool.h -D__bool_true_false_are_defined=1",
            "-std=c99",
        )
    };

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let zkey_dir = std::path::Path::new(&manifest_dir).join("zkey_tmp");

    // println!("cargo::rustc-link-lib=stdbool");

    // transpile_wasm adds a cargo directive that causes recompilation when files in circom_output
    // change. Since we are creating these files this means the crate will always be considered
    // ddirty. Luckily it is the first line emitted, so we can add a prefix to disable it.
    // print!("IGNORED CARGO DIRECTIVE: ");

    // Searches the directory recursively for wasm files.
    // Why does everyone want owned strings for no reason?
    // transpile_wasm(circom_output.to_owned());
    transpile_wasm(zkey_dir.to_string_lossy().to_string());
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
