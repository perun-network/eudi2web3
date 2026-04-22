pragma circom 2.2.3;

include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/bitify.circom";

template BEBits2Array(n, k) {
    // We could allow other sizes, but then it's not obvious what needs to be padded.
    assert(n%k == 0);

    signal input bits[n]; // binary
    signal output out[k];

    // Calculate the required size for Bits2Num (last one can be shorter).
    var size = (n+k-1)\k; // div_ceil

    // Create the components
    component b2n[k];
    for (var i = 0; i < k; i++) {
        b2n[i] = Bits2Num(size);
        for (var x = 0; x < size; x++) {
            b2n[i].in[size-1-x] <== bits[i*size+x];
        }
    }

    // Wire up the output
    for (var i = 0; i < k; i++) {
        out[i] <== b2n[i].out;
    }
}


template Example(payload_bytes) {
    signal input in[payload_bytes*8];
    signal input dotSep;
    var MAX_HEADER_SIZE = 16;

    signal payload_b[payload_bytes] <== BEBits2Array(payload_bytes*8, payload_bytes)(in);

    assert(dotSep < MAX_HEADER_SIZE);
    component dotCheck = Multiplexer(1,MAX_HEADER_SIZE);
    for (var i = 0; i < MAX_HEADER_SIZE; i++) {
        dotCheck.inp[i][0] <== payload_b[i];
    }
    dotCheck.sel <== dotSep;
}

component main = Example(64);

