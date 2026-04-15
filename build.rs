fn main() {
    let mut libs: Vec<String> = std::fs::read_dir("zkey/lib")
        .unwrap()
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

    println!("cargo:rerun-if-changed=zkey/lib/");
    println!("cargo:rustc-link-search=native=zkey/lib");
    for name in libs {
        println!("cargo:rustc-link-lib=static={name}");
        println!("cargo:rerun-if-changed=zkey/lib/lib{name}.a");
    }
}
