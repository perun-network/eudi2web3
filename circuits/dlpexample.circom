pragma circom 2.0.0;

// To prove knowledge of factors. Doesn't prove whether they are prime.
template DlpExample {
    signal input a;
    signal input b;
    signal output product;

    product <== a * b;
}

component main = DlpExample();

