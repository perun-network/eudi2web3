pragma circom 2.2.3;

include "circomlib/circuits/multiplexer.circom";

template Example(payload_bytes) {
    signal input in[payload_bytes];
    var SIZE = 4;

    component dotCheck = Multiplexer(1,SIZE);
    for (var i = 0; i < SIZE; i++) {
        dotCheck.inp[i][0] <== in[i];
    }
    dotCheck.sel <== 1;
}

component main = Example(8);

