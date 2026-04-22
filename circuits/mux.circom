pragma circom 2.2.3;

include "circomlib/circuits/multiplexer.circom";

template Demo {
    signal input in;
    signal output out;

    component dotCheck = Multiplexer(1,2);
    dotCheck.inp[0][0] <== 0;
    dotCheck.inp[1][0] <== in;
    dotCheck.sel <== 1;
    dotCheck.out[0] ==> out;
}
/*
template Decoder {
    signal input inp;
    signal output out[2];
    signal output success;
    var lc=0;

    for (var i=0; i<2; i++) {
        out[i] <-- (inp == i) ? 1 : 0;
        out[i] * (inp-i) === 0;
        lc = lc + out[i];
    }

    lc ==> success;
    success * (success -1) === 0;
}

template Demo {
    signal input in;
    signal output out;

    component dec = Decoder();

    1 ==> dec.inp;
    out <== in * dec.out[1];

    dec.success === 1;
}

template Decoder {
    signal output out[2];
    signal output success;

    out[0] <== 0;
    out[1] <-- 1;

    1 ==> success;
}

template Demo {
    signal input in;
    signal output out;

    component dec = Decoder();

    out <== in * dec.out[1];

    dec.success === 1;
}
*/

// Proofs for this circuit generated with Arkworks + RustWitness:
// - Fail if the input json has signals as string (decimal)
// - Fail if the input is the HashMap directly
// - Succeed if the input json has signals as numbers
/*
template Demo {
    signal input in;
    signal output out;

    signal x <-- 1;
    out <== in * x;
}
// */
component main = Demo();



