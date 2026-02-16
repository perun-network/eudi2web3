pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";
include "util.circom";


// n: Max number of bytes
// k: Max Key length
// v: Max value length
//
// Aignals are in bytes
// This assumes the data is valid json. If it isn't there isn't much of a guarantee.
// The output will contain quotes and escape sequences for strings.
// 
// This is implemented as a verifier and not a "extract key/value" because this is likely more efficient and sufficient for our use.
//
// # Known Issues
// Do not use the keys that only contain valid json structure (examples below). This template cannot distinguish between those keys
// and parts of the json structure and thus can result in the constraints succeeding if the value doesn't match.
// - ':' (optionally with whitespaces) => Can match any key value pair as long as the value is a string and starts with `:`.
//   if the user can choose any string value starting with ':' he can choose an arbitrary value for these keys.
// - ',' (optionally with whitespaces) => Same as above if the user can have/choose an arbitrary KEY starting with ':'
// - 'true', 'false', brackets or any number => Same as above
// - Keys ending with a partial escape sequence.
template JsonCheckKeyValue(n, k, v) {
    assert(k + v < n);

    signal input data[n]; // Must start with the character before the Key quote
    // Any key signals that are 0 are not checked against data. This is intended to be used for the length, but
    // technically the 0 signals can also be in the middle of the key, resulting in a wildcard.
    signal input key[k];
    // Needed to verify the structure. This should be part of the output, as we (currently) do not enforce that this matches key.
    signal input key_length;
    // As with the key: Input signals that are 0 are not checked against data. This includes quotes and brackets and might be
    // truncated or longer than the actual value. This template does not check the value length.
    signal input value[v];


    // Make sure the starting quote is not escaped. This makes sure we don't start somewhere in the middle of a string.
    // It is still possible that we are starting at the end of a string.
    signal escaped <== IsZero()(data[0] - 92); // '\'
    escaped === 0;
    data[1] === 34; // '"'
    
    component gap = SliceFixedLenV2(2, k+2);
    for (var i = 0; i < k+2; i++) {
        gap.in[i] <== data[i+2];
    }
    gap.sel <== key_length;

    // For now we're forcing minified (or at least sane) JSON formatting
    gap.out[0] === 34; // '"'
    gap.out[1] === 58; // ':'

    // Check the key matches
    for (var i = 0; i < k; i++) {
        // key[i] == 0 || key[i] == data[i+1]
        key[i] * (key[i] - data[i+2]) === 0;
    }

    // Select/Shift the value bytes.
    component valueSel = SliceFixedLenV2(v, n-4);
    for (var i = 0; i < n-4; i++) {
        valueSel.in[i] <== data[i+4];
    }
    valueSel.sel <== key_length;

    // Check the value matches
    for (var i = 0; i < v; i++) {
        value[i] * (value[i] - valueSel.out[i]) === 0;
    }
}

