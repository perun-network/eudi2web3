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

// Same as Num2Bits but ignores the bits above n.
template Num2BitsTruncate(n) {
    signal input in;
    signal output out[n];

    var e2=1;
    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] -1 ) === 0;
        e2 = e2+e2;
    }
}

// Takes a slice of signals from the input: out = in[offset..offset+w].
// It is just a convenience wrapper around Multiplexer (which is more flexible).
//
// PERFORMANCE: After implementing this I noticed that zk-email-verify has a similar function
//              (which additionally has a length signal and sets the bits after it to 0,
//              instead of forcing the entire slice to fit like we do).
//              Probably worth testing which one is more efficient.
//              This implementation also has some downsides/limits when the data is close to the end.
template SliceFixedLen(w, n) {
    assert(w < n);
    signal input in[n];
    signal input sel;
    signal output out[w];

    component mul = Multiplexer(w, n-w);
    for (var i = 0; i < n-w; i++) {
        for (var o = 0; o < w; o++) {
            mul.inp[i][o] <== in[i+o];
        }
    }
    mul.sel <== sel;
    out <== mul.out;
}

template SliceFixedLenV2(w, n) {
    assert(w <= n);
    signal input in[n];
    signal input sel;
    signal output out[w];

    component mul = Multiplexer(w, n);
    for (var i = 0; i < n; i++) {
        for (var o = 0; o < w; o++) {
            mul.inp[i][o] <== i+o<n ? in[i+o] : 0;
        }
    }
    mul.sel <== sel;
    out <== mul.out;
}
