pragma circom 2.2.3;

include "circom-ecdsa-p256/circuits/ecdsa.circom";
include "zk-email-verify/packages/circuits/lib/sha.circom";
include "circomlib/circuits/bitify.circom";

// 6*u43 is the format prefered/used by the library (even though it seems to allow other k).
bus Signature {
    // @type: u43
    signal r[6];
    // @type: u43
    signal s[6];
}

bus Disclosure(sdbytes) {
    // @type: binary
    // Format: Padded according to sha2 spec, might not use all blocks.
    signal data[sdbytes*8];
    // @type: u64
    signal length;
}

bus Location {
    // PERFORMANCE: We probably want this to be constant and only store a single bit to specify where the value is.
    // @type: u64
    signal sd_idx;        // The disclosure index that contains the value (0 means no separate disclosure entry).
    // @type: u64
    signal offset;        // Offset in bytes (after base64 decoding) where the object entry starts (first quote).
    // @type: u64
    signal length;        // When the value ends.
    // @type: u64
    signal hash_offset;   // Offset to the entry in _sd.
}

bus SDJWT(payload_bytes, num_sd, sdbytes, path_depth) {
    // @type: u128
    signal pk[2][6];                     // Issuer public key
    Signature sig;                                  // Part 1.3
    // @type: binary
    // Format: Padded according to sha2 spec, might not use all blocks.
    signal payload[payload_bytes*8];       // Part 1.(1+2):    base64(jwt_header) + '.' + base64(jwt_body)
    // @type: u64
    signal payloadLength;
    // Disclosure(sdbytes) disclosures[num_sd];        // Part 2-n:        base64(json(disclosure_entry))

    // Additional information (unless we compute- that in witness generation)
    // @type: u64
    // signal body_start;                        // Offset into payload where the '.' separator is.
    // Location steps[path_depth];
}

// If k does not divide bits the last signals high bits will be 0.
// Each number in the array will be least-significant-bit first. The first n/k bits are at index 0.
// TODO: I'm not sure if the behavior if k doesn't divide n is correct/desired.
template Bits2ArrayLE(n, k) {
    signal input bits[n]; // binary
    signal output out[k];

    // Calculate the required size for Bits2Num (last one can be shorter).
    var size = (n+k-1)\k; // div_ceil
    var last = n-size*(k-1);

    // Create the components
    component b2n[k];
    for (var i = 0; i < k-1; i++) {
        b2n[i] = Bits2Num(size);
    }
    b2n[k-1] = Bits2Num(last);

    // Wire up the bits to the corresponding Bits2Num instances
    for (var i = 0; i < n; i++) {
        b2n[i\size].in[i%size] <== bits[i];
    }

    // Wire up the output
    for (var i = 0; i < k; i++) {
        out[i] <== b2n[i].out;
    }
}
template Bits2ArrayBE(n, k) {
    signal input bits[n]; // binary
    signal output out[k];

    // Calculate the required size for Bits2Num (last one can be shorter).
    var size = (n+k-1)\k; // div_ceil
    var last = n-size*(k-1);

    // Create the components
    component b2n[k];
    for (var i = 0; i < k-1; i++) {
        b2n[i] = Bits2Num(size);
    }
    b2n[k-1] = Bits2Num(last);

    // Wire up the bits to the corresponding Bits2Num instances
    for (var i = 0; i < n; i++) {
        b2n[i\size].in[size-1-i%size] <== bits[i];
    }

    // Wire up the output
    for (var i = 0; i < k; i++) {
        out[i] <== b2n[i].out;
    }
}

template SDJWT_ES256_SHA256_1claim(payload_bytes, num_sd, sdbytes, path_depth) {
    input SDJWT(payload_bytes, num_sd, sdbytes, path_depth) in;

    // Canary to detect when rust_witness doesn't have all inputs. Can be removed.
    signal output test <== 99;

    signal hash_bin[256];

    // Compute hash of JWT header+body
    // TODO: I don't think this verifies if the padding is correct, which could be an attack vector.
    hash_bin <== Sha256General(payload_bytes*8)(
        paddedIn <== in.payload,
        paddedInLength <== in.payloadLength
    );

    // output the hash in decimal bytes, useful for debugging the hash inputs.
    signal output hash_bytes[32] <== Bits2ArrayBE(256,32)(hash_bin);

    // // Sha outputs in binary, ECDSA expects 6*u43, so we have to convert.
    // signal hash[6] <== Bits2Array(256, 6)(hash_bin);

    // // Check signature
    // var valid = ECDSAVerifyNoPubkeyCheck(43, 6)(
    //     r <== in.sig.r,
    //     s <== in.sig.s,
    //     pubkey <== in.pk,
    //     msghash <== hash
    // );
    // assert(valid);
    // valid === 1;

    // How the hell do you translate that into a circuit template?
    // 1. Verify in.payload against in.sig (ECDSA_P256_SHA256_FIXED)
    // 2. Base64 decode in.payload[in.body_start..] ==> body
    // 3. For each s in in.steps
    //  3.1. alwaysValue <== FindKeyInJson(body, <key>)
    //  3.2. hash <== FindSdEntyinJson(body, idx)
    //  3.3. Compute hash of disclosure for this step
    //  3.4. Check hash
    //  3.5. If s.is_sd: Compare hash against expected value
    //  3.6. ...

    //  3.1: If s.sd_idx: continue with value body['key']
    //  3.2: Else: SHA256(in.disclosures[in.steps[i].sd_idx]) ==> hash
    //  3.3:       Check base64(hash) == data[in.steps[i].hash_offset..]
    //  3.4:       continue 
}

component main = SDJWT_ES256_SHA256_1claim(1024, 3, 200, 2);
