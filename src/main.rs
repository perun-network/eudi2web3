use prover::MultiuseProver;

// Generated code to go from input to witness.
mod witness {
    rust_witness::witness!(dlpexample);
}

mod mdoc;
mod prover;
mod sdjwt;

fn main() {
    sdjwt::explore();

    println!();
    println!("{}", "-".repeat(64));
    println!();

    mdoc::explore();

    println!();
    println!("{}", "-".repeat(64));
    println!();

    /////////////////////////////////////////////////////////////////////////////////////
    // ZK Circuit (proof creation)
    /////////////////////////////////////////////////////////////////////////////////////

    let zkey_path = "zkey/dlpexample.zkey";
    let prover = MultiuseProver::new(zkey_path).unwrap();

    let input = [
        ("a".to_owned(), vec![3.into()]),
        ("b".to_owned(), vec![7.into()]),
    ];
    let proof = prover.prove(witness::dlpexample_witness, input).unwrap();
    dbg!(&proof);
}
