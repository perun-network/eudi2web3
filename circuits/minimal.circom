pragma circom 2.2.3;

// Tiny/Minimal circuit that allows us to test everything around the circuit without needing
// to compute large/expensive proofs. The goal is to be compatible with the on-chain circuit,
// but with minimal in-circuit work (also having minimal private inputs).
template Minimal {
    var MAX_VALUE_SIGNALS = 2;

    signal input value_compressed[MAX_VALUE_SIGNALS];
    signal input valid;

    valid === 65; // 'A'
}

component main {public [value_compressed]} = Minimal();
