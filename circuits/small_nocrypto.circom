pragma circom 2.2.3;

include "core.circom";

component main = Core(
    32,      // header
    192,    // payload
    1,      // sd_entries
    1,      // disclosures
    192,    // sdbytes
    1,      // path_depth
    0       // do_crypto
);

