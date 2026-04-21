pragma circom 2.2.3;

// Non-functional witness generation tends to output only 0 signals and the inputs we give it.
// This circuit is to test whether witness generation functions.
template Minimal {
    signal output foo <== 42;
    // Various lines for testing logging (manually).
    log("AAAAAAAA");
    log(foo);
    // NOTE: assert currently does not result in an actual error on the rust side, it is only
    // printed to stdout and does not impact witness data or proof validity.
    // If that changes in the future: Good, remove this line.
    assert(foo == 1);
}

component main = Minimal();

