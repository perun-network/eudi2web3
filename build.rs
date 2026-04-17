use std::{io::ErrorKind, io::Write};

fn main() {
    // Get the list of witness generation .a files.
    let libs = match std::fs::read_dir("zkey/lib") {
        Ok(dir) => {
            let mut libs: Vec<String> = dir
                .filter_map(|e| {
                    let e = e.unwrap();
                    if !e.file_type().unwrap().is_file() {
                        return None;
                    }
                    let name = e.file_name();
                    Some(
                        name.to_str()?
                            .strip_prefix("lib")?
                            .strip_suffix(".a")?
                            .to_string(),
                    )
                })
                .collect();
            libs.sort();
            libs
        }
        Err(e) if e.kind() == ErrorKind::NotFound => vec![],
        Err(e) => panic!("Error while iterating zkey/lib: {e}"),
    };

    // Tell cargo to link them and watch for changes in that directory.
    println!("cargo:rerun-if-changed=zkey/lib/");
    println!("cargo:rustc-link-search=native=zkey/lib");
    for name in &libs {
        println!("cargo:rustc-link-lib=static={name}");
        // Unsure if needed, probably not but it doesn't hurt.
        println!("cargo:rerun-if-changed=zkey/lib/lib{name}.a");
    }

    let linked: Vec<(&str, &str)> = libs.iter().map(|s| s.split_once('_').unwrap()).collect();

    // If we have a witness macro call but the .a file is not linked compilation fails.
    // To avoid that we make sure they both work on the same set of files.
    let out = std::env::var("OUT_DIR").unwrap();
    let path = format!("{out}/witness_codegen.rs");
    let mut f = std::fs::File::create(path).unwrap();
    // Add code for using the w2c2 generated code.
    for (curve, circuit) in &linked {
        let name = curve.to_string() + circuit;
        let name = name.replace('-', "");
        writeln!(f, "rust_witness::witness!({name});").unwrap();
        // Because we store it in a const &[] we need a shim/wrapper function to convert it into a
        // non-generic function. Closures don't work either.
        writeln!(
            f,
            "fn {name}_shim(i: Vec<(String, Vec<BigInt>)>) -> Vec<BigInt> {{ {name}_witness(i) }}"
        )
        .unwrap();
    }
    // Provide the list of linked witness generation .a files and their relevant entry points.
    // Note: This depends on the type definition already being present.
    writeln!(f, "\nconst LINKED: &[LinkedLib] = &[").unwrap();
    for (curve, circuit) in &linked {
        let name = curve.to_string() + circuit;
        let name = name.replace('-', "");
        writeln!(
            f,
            "    LinkedLib {{ curve: {curve:?}, circuit: {circuit:?}, compute_witness: {name}_shim }},"
        )
        .unwrap();
    }
    writeln!(f, "];").unwrap();
    f.flush().unwrap();
}
