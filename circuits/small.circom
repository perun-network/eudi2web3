pragma circom 2.2.3;

include "core.circom";

// Header unfortunately includes an x5c certificate chain
component main = Core(
    2048,   // header
    3072,   // payload
    8,     // sd_entries
    1,      // disclosures
    128,    // sdbytes
    2,      // path_depth
    1       // do_crypto
);
