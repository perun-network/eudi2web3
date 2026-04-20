pragma circom 2.2.3;

include "to_be_named.circom";

// Header unfortunately includes an x5c certificate chain
component main = SDJWT_ES256_SHA256_1claim(2048, 4096, 10, 1, 256, 2, 1);

