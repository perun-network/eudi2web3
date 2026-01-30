use prover::MultiuseProver;

// Generated code to go from input to witness.
mod witness {
    rust_witness::witness!(dlpexample);
}

mod prover;
mod sdjwt;

fn main() {
    sdjwt::explore();

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
