pragma circom 2.2.3;

include "core.circom";

// Header unfortunately includes an x5c certificate chain
component main = Core(
    2048,   // header
    4096,   // payload
    10,     // sd_entries
    1,      // disclosures
    256,    // sdbytes
    2,      // path_depth
    1       // do_crypto
);
