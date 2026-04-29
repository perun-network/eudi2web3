pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";
include "util.circom";
include "zk-email-verify/packages/circuits/lib/bigint-func.circom";


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
    // Separating character (usually ':'). Having this configurable allows us to use this template for both objects and SD entries.
    signal input sep;

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
    gap.out[1] === sep; // ':'

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

// It makes sure we are processing an array with name `key` (in an object of course).
// It makes sure value (a fixed length string) is in that array.
//
// TODO: Add the following
// It makes sure we stay within that array
//
// PERFORMANCE: It may be beneficial to work on the base64 encoded bytes.
// That makes this more complex but we don't need to check the entire base64 string.
template JsonGetSDEntry(n) {
    var nlog2 = log_ceil(n);
    log(nlog2);

    // Minimal input consists of "_sd":["<43_base64_bytes>"
    assert(52 < n);

    signal input data[n];
    signal input distance2quote;
    signal output value[43];

    signal escaped <== IsZero()(data[0] - 92); // '\'
    escaped === 0;
    data[1] === 34; // '"'
    data[2] === 95; // '_'
    data[3] === 115; // 's'
    data[4] === 100; // 'd'
    data[5] === 34; // '"'
    data[6] === 58; // ':'

    // Make sure there is no array closing in-between, so we are still withing the '_sd' array
    component lt[n-8];
    component eq[n-8];
    for (var i = 0; i < n-8; i++) {
        lt[i] = LessThan(nlog2);
        lt[i].in[0] <== i;
        lt[i].in[1] <== distance2quote;

        eq[i] = IsEqual();
        eq[i].in[0] <== data[i];
        eq[i].in[1] <== 93;

        lt[i].out * eq[i].out === 0; // In range && ']'
    }

    // Select/Shift the value bytes
    component valueSel = SliceFixedLenV2(45, n-8);
    for (var i = 0; i < n-8; i++) {
        valueSel.in[i] <== data[i+8];
    }
    valueSel.sel <== distance2quote;

    // Check the value matches
    valueSel.out[0] === 34; // '"'
    valueSel.out[44] === 34; // '"'
    for (var i = 0; i < 43; i++) {
        value[i] <== valueSel.out[1+i];
    }
}
