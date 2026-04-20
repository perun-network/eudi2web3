pragma circom 2.2.3;

include "core.circom";

// Header unfortunately includes an x5c certificate chain
component main = Core(2048, 4096, 10, 1, 256, 2, 1);

