use crate::witness::CircuitId;

#[test]
fn test_wtns_gen_working() {
    let id = CircuitId {
        curve: "bn254".to_owned(),
        circuit: "witness_test".to_owned(),
        contributions: 1,
    };
    let circuits = super::get_circuits();
    dbg!(&circuits);
    let e = circuits.get(&id).unwrap();

    let input = vec![];
    let wit = (e.compute_witness)(input);
    dbg!(&wit);
    assert_eq!(
        wit.len(),
        2,
        "did the circuit implementation change to have a larger witness?"
    );
    assert_eq!(wit[0], 1.into());
    assert_eq!(wit[1], 42.into());
}
