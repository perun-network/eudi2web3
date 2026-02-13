pragma circom 2.2.3;

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

template BEBits2Limbs {
    signal input bits[256]; // binary
    signal output out[6];

    component b2n[6];

    for (var i = 0; i < 6; i++) {
        b2n[i] = Bits2Num(43);
        for (var j = 0; j < 43; j++) {
            var bitPos = i * 43 + j;
            if (bitPos < 256) {
                // sha.out is most significant bit first. Reverse to obtain least significant bit first numeric interpretation
                b2n[i].in[j] <== bits[255 - bitPos];
            } else {
                b2n[i].in[j] <== 0;
            }
        }
        out[i] <== b2n[i].out;
    }
}

