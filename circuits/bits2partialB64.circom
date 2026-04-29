pragma circom 2.2.3;

include "base64.circom";
include "util.circom";
include "circomlib/circuits/multiplexer.circom";

/*
# IMPORTANT
The offset MUST be at a base64 boundry, otherwise the data returned is not the encoded data.
The templates below do not assert for this because the start of the base64 data may not be at 0.
It is up to the caller to ensure the offset is actually at a base64 block start.

# Which version should I use
V3 (only if base64_start%4 == 0) has the lowest number of constraints and has been consistantly the fastest in witness generation:
V4/5 are currently the most efficient one if the base64 can start at an arbitrary offset,
   but depending on teh configuration V1 or V6 could be better.
V6 has fewer constraints than V4/5 at 256/4096 bytes.
V2 was mostly out of curiosity how bad it really is. Don't use it.

For selecting 16/128 base64 bytes:

$ circom circuits/tests/test-circuits/bits2partialB64_1.circom -o /tmp/c -l circuits --r1cs
template instances: 14
non-linear constraints: 3184
linear constraints: 589
public inputs: 0
private inputs: 1025
public outputs: 12
wires: 4670
labels: 12969

$ circom circuits/tests/test-circuits/bits2partialB64_2.circom -o /tmp/c -l circuits --r1cs
template instances: 14
non-linear constraints: 116864
linear constraints: 590
public inputs: 0
private inputs: 1025 (1024 belong to witness)
public outputs: 12
wires: 118350
labels: 463433

$ circom circuits/tests/test-circuits/bits2partialB64_3.circom -o /tmp/c -l circuits --r1cs
template instances: 18
non-linear constraints: 1564
linear constraints: 534
public inputs: 0
private inputs: 1025
public outputs: 12
wires: 2975
labels: 6158

$ circom circuits/tests/test-circuits/bits2partialB64_4.circom -o /tmp/c -l circuits --r1cs
template instances: 25
non-linear constraints: 1692
linear constraints: 566
public inputs: 0
private inputs: 1025
public outputs: 12
wires: 3129
labels: 7714

$ circom circuits/tests/test-circuits/bits2partialB64_5.circom -o /tmp/c -l circuits --r1cs
template instances: 25
non-linear constraints: 1687
linear constraints: 558
public inputs: 0
private inputs: 1025
public outputs: 12
wires: 3114
labels: 7571

$ circom circuits/tests/test-circuits/bits2partialB64_6.circom -o /tmp/c -l circuits --r1cs
template instances: 25
non-linear constraints: 1862
linear constraints: 572
public inputs: 0
private inputs: 1025
public outputs: 12
wires: 3296
labels: 8077
*/

// (1024, 64) => 70386 constraints, 78067 wires
// Witness generation: 0.299 seconds
template bits2partialB64DecodeV1(payload_bytes, max_b64_len) {
    // Make sure we're getting complete base64 blocks.
    assert(max_b64_len % 4 == 0);
    assert(max_b64_len <= payload_bytes);

    signal input bits[payload_bytes * 8];
    signal input offset;
    signal output out[max_b64_len*3/4];

    // Convert bits to bytes
    signal b64[payload_bytes] <== BEBits2Array(payload_bytes*8, payload_bytes)(bits);
    
    // Select which bytes we want to decode.
    signal slice[max_b64_len] <== SliceFixedLenV2(max_b64_len, payload_bytes)(
        in <== b64,
        sel <== offset
    );

    // Base64 decode
    component dec = Base64Decode(max_b64_len/4*3);
    dec.in <== slice;
    out <== dec.out;
}

// I strongly suspect this will be worse than v1 because the multiplexer likely has more constraints than b2n.
// (1024, 64) => Unknown, compilation takes forever.
template bits2partialB64DecodeV2(payload_bytes, max_b64_len) {
    // Make sure we're getting complete base64 blocks.
    assert(max_b64_len % 4 == 0);
    assert(max_b64_len <= payload_bytes);

    signal input bits[payload_bytes * 8];
    signal input offset;
    signal output out[max_b64_len*3/4];

    // Select which bytes we want to decode.
    signal slice[max_b64_len*8] <== SliceFixedLenV2(max_b64_len*8, payload_bytes*8)(
        in <== bits,
        sel <== offset*8
    );

    // Convert bits to bytes
    signal b64[max_b64_len] <== BEBits2Array(max_b64_len*8, max_b64_len)(slice);

    // Base64 decode
    component dec = Base64Decode(max_b64_len/4*3);
    dec.in <== b64;
    out <== dec.out;
}

// Idea for another version: Combine bits into u32 or u64 (instead of u8), multiplex on that and then go back to u8.
// Might be worth to avoid multiplexer complexity and we need to start at a b64 block boundry anyways.
// (1024, 64) => 12034 constraints, 19635 wires
// Witness generation: 0.122 seconds
//
// IMPORTANT: This does not allow a base offset (i.e. the base64 data starting at an index that is not a multiple of 4).
//            Often this is fine, but that is problematic for the JWT body, which starts after the header (arbitrary length
//            because its base64 doesn't have padding).
// PERFORMANCE: We might be able to further improve this by using u64, but that does change the start byte of base64 slightly.
//              also see V4-6. This would either change the output behavior slightly (could be worth it) or it would require
//              adding a multiplexer similar to V4-6 (but that one would be simpler as it has fewer selection options).
template bits2partialB64DecodeV3(payload_bytes, max_b64_len) {
    // Make sure we're getting complete base64 blocks.
    assert(max_b64_len % 4 == 0);
    assert(max_b64_len <= payload_bytes);

    signal input bits[payload_bytes * 8];
    signal input offset;
    signal output out[max_b64_len*3/4];

    // This version does not support base64 starting at an offset or offset not pointing to a base64 block.
    // Use V1 or V4 instead if the first one is required.
    // Multiplex after base64 decoding if the second one is required (same for all other versions we have now).
    assert(offset % 4 == 0);
    
    var in_blocks = payload_bytes / 4;
    var out_blocks = max_b64_len / 4;

    // Convert a format that is more beneficial for Multiplexer.
    signal blocks[in_blocks] <== BEBits2Array(payload_bytes*8, in_blocks)(bits);

    // Select which bytes we want to decode.
    signal slice[out_blocks] <== SliceFixedLenV2(out_blocks, in_blocks)(
        in <== blocks,
        sel <== offset/4
    );

    // Convert back to the format Base64Decoder expects
    signal b64[max_b64_len] <== uArr_to_be_bytes(out_blocks,4)(slice);

    // Base64 decode
    component dec = Base64Decode(max_b64_len/4*3);
    dec.in <== b64;
    out <== dec.out;
}

template bits2partialB64DecodeV4(payload_bytes, max_b64_len) {
    signal input bits[payload_bytes * 8];
    signal input offset;
    signal output out[max_b64_len*3/4];

    out <== bits2partialB64Decode_multibyteMux_offset(payload_bytes, max_b64_len, 2)(bits, offset);
}
template bits2partialB64DecodeV5(payload_bytes, max_b64_len) {
    signal input bits[payload_bytes * 8];
    signal input offset;
    signal output out[max_b64_len*3/4];

    out <== bits2partialB64Decode_multibyteMux_offset(payload_bytes, max_b64_len, 3)(bits, offset);
}
template bits2partialB64DecodeV6(payload_bytes, max_b64_len) {
    signal input bits[payload_bytes * 8];
    signal input offset;
    signal output out[max_b64_len*3/4];

    out <== bits2partialB64Decode_multibyteMux_offset(payload_bytes, max_b64_len, 4)(bits, offset);
}

// Perhaps I should stop trying to improve this.
// Because we need a second multiplexer to allow base64 start offsets, we could just as well make the first one more efficient
// by using u128. Note that this does increase the second multiplexer size and thus may be worse than V4 (depends on configuration).
// This one also is slightly more restrictive when it comes to being near the end of the payload.
template bits2partialB64Decode_multibyteMux_offset(payload_bytes, max_b64_len, k) {
    var b = 1 << k;
    // Make sure we're getting complete base64 blocks.
    assert(max_b64_len % b == 0);
    assert(max_b64_len <= payload_bytes);
    assert(payload_bytes % b == 0);

    signal input bits[payload_bytes * 8];
    signal input offset;
    signal output out[max_b64_len*3/4];

    var in_blocks = payload_bytes / b;
    var out_blocks = max_b64_len / b + 1; // Alginment requires a bit more data at the end.

    // Get the inner selection (offset has to point to a block start, as with all other versions).
    signal off_bits[k] <== Num2BitsTruncate(k)(offset);
    signal rem <== Bits2Num(k)(off_bits);
    signal div <== (offset - rem)/b;

    // Convert a format that is more beneficial for Multiplexer.
    signal blocks[in_blocks] <== BEBits2Array(payload_bytes*8, in_blocks)(bits);

    // Select which bytes we want to decode.
    signal slice[out_blocks] <== SliceFixedLenV2(out_blocks, in_blocks)(
        in <== blocks,
        sel <== div
    );

    // Convert back to the format Base64Decoder expects
    signal b64[max_b64_len+b] <== uArr_to_be_bytes(out_blocks, b)(slice);

    // Align the base64 blocks.
    // To allow arbitrary base64 start offsets we either need a different base64 decoder implementation
    // or we need another multiplexer. Doing this here (on a smaller set of inputs) might be faster
    // than doing it on the entire input (as V1 does).
    signal aligned[max_b64_len] <== SliceFixedLenV2(max_b64_len, max_b64_len+b)(
        in <== b64,
        sel <== rem
    );

    // Base64 decode
    component dec = Base64Decode(max_b64_len/4*3);
    dec.in <== aligned;
    out <== dec.out;
}


// Takes an array of 32 bit unsigned ints as input and returns their big-endian bytes.
template uArr_to_be_bytes(n, k) {
    signal input in[n];
    signal output out[n*k];

    component conv[n];
    for (var i = 0; i < n; i++) {
        conv[i] = unsigned_to_be_bytes(k);
        conv[i].in <== in[i];
        for (var x = 0; x < k; x++) {
            out[k*i+x] <== conv[i].out[x];
        }
    }
}

// Takes a 8*k bit unsigned int as input and returns 4 bytes (MSB first)
// Copied and adjusted form Num2Bits.
// The LessThan check might not be neccesary if the base64 implementation rejects large signals.
template unsigned_to_be_bytes(k) {
    signal input in;
    signal output out[k];
    var lc1=0;

    var e2=1;
    component lt[k];
    for (var i = 0; i<k; i++) {
        out[k-1-i] <-- (in >> 8*i) & 255;
        lt[i] = LessThan(8);
        lt[i].in[0] <== out[k-1-i];
        lt[i].in[1] <== 256;
        lt[i].out === 1;
        lc1 += out[k-1-i] * e2;
        e2 = 256*e2;
    }

    lc1 === in;
}

