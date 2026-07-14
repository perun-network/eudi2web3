pragma circom 2.2.3;

include "zk-email-verify/packages/circuits/lib/sha.circom";

template OnlySha {
    signal input in[512];
    signal output out[256];

    component hasher = Sha256General(512);
    hasher.paddedIn <== in;
    hasher.paddedInLength <== 512;
    hasher.out ==> out;
}

component main = OnlySha();



