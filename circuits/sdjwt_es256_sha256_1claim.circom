pragma circom 2.2.3;

include "circom-ecdsa-p256/circuits/ecdsa.circom";
include "zk-email-verify/packages/circuits/lib/sha.circom";
include "circomlib/circuits/bitify.circom";
include "bits2partialB64.circom";
include "json.circom";

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

    // Position of the dot separator between JWT header and body.
    signal dotSep;

    // Index into payload where the interesting data starts. Must point to the start of a block in the body,
    // even though the offset is from the start of header (all base64 encoded, including the separating dot).
    // TODO: We may want to change this at some point.
    // @type: u64
    signal payloadOff;
    // Value between 0 and 2 to go from base64 block alignment to the json start (character before quote)
    signal jsonAlign;
}


template SDJWT_ES256_SHA256_1claim(payload_bytes, num_sd, sdbytes, path_depth) {
    // Including the '.' separator, before base64 decoding
    var MAX_HEADER_SIZE = 2048; // Sadly includes x5c (certificate chain)
    var MAX_BYTES = 96;
    var MAX_KEY = 10;
    var MAX_VALUE = 64;

    var CHECK_SIG = 1; // 0: false, 1:true

    input SDJWT(payload_bytes, num_sd, sdbytes, path_depth) in;
    signal input value[MAX_VALUE]; // 0-padded

    // Canary to detect when rust_witness doesn't have all inputs. Can be removed.
    // signal output test <== 99;

    // var key[MAX_KEY] = [103, 105, 118, 101, 110, 95, 110, 97, 109, 101]; // "given_name"
    // var key_length = 10;
    var key[MAX_KEY] = [105, 115, 115, 0, 0, 0, 0, 0, 0, 0]; // "iss"
    var key_length = 3;

    assert(MAX_BYTES % 3 == 0);
    var MAX_BASE64 = MAX_BYTES / 3 * 4;

    if (CHECK_SIG != 0) {
        // Compute hash of JWT header+body
        // TODO: I don't think this verifies if the padding is correct, which could be an attack vector.
        // For payload_bytes=1024:   524.563 constraints (approx.)
        // For payload_bytes=2048: 1.049.364 constraints (approx.)
        // For payload_bytes=4096: 2.098.965 constraints (approx.)
        signal hash_bin[256] <== Sha256General(payload_bytes*8)(
            paddedIn <== in.payload,
            paddedInLength <== in.payloadLength
        );

        // // output the hash in decimal bytes, useful for debugging the hash inputs.
        // signal hash_bytes[32] <== BEBits2Array(256,32)(hash_bin);
        // log("Hash:");
        // for (var i = 0; i < 32; i++) {
        //     log(hash_bytes[i]);
        // }

        // Check signature
        // Regardless of configuration: 2.220.351 constraints
        signal hash[6] <== BEBits2Limbs()(hash_bin);
        var valid = ecdsa__ECDSAVerifyNoPubkeyCheck(43, 6)(
            r <== in.sig.r, 
            s <== in.sig.s,
            pubkey <== in.pk,
            msghash <== hash
        );
        assert(valid);
        valid === 1;
    }

    // We are looking for a json key-value pair: `"key":.*[,}\]]` inside the base64.
    // The base64 decoder we currently have is not sha2 padding aware, so we should
    // stay in-bounds or we need special handling for padding.

    // PERFORMANCE: We should only do this conversion once, but that is difficult if we don't know
    // which version of bits2partialB64 we will use. Ideally we'd use the same here, reuse the representation
    // and just have a second Multiplexer that has it as input. Then we just need to split it back up into
    // bytes and multiplex on that, same as we do for bits2partialB64. For now I'm taking the simpler
    // approach of doing the signal conversion twice (directly to bytes in this case), even if it is likely
    // less efficient.
    signal payload_b[payload_bytes] <== BEBits2Array(payload_bytes*8, payload_bytes)(in.payload);

    // Make sure the dotSep position is correct (without this a malicious user could try to get us
    // to decode base64 with a wrong offset and make us believe we're at the key while we are
    // somewhere in arbitrary data).
    assert(in.dotSep < MAX_HEADER_SIZE);
    component dotCheck = Multiplexer(1,MAX_HEADER_SIZE);
    for (var i = 0; i < MAX_HEADER_SIZE; i++) {
        dotCheck.inp[i][0] <== payload_b[i];
    }
    dotCheck.sel <== in.dotSep;
    dotCheck.out[0] === 46; // '.' character

    // Make sure we are decoding from the payload body
    component bodyCheck = LessThan(32);
    bodyCheck.in[0] <== in.dotSep;
    bodyCheck.in[1] <== in.payloadOff;
    bodyCheck.out === 1;
    assert(bodyCheck.out == 1);

    // Make sure our base64 decoding is properly aligned.
    // (in.payloadOff-in.dotSep) % 4 == 1
    signal rem[2] <== Num2BitsTruncate(2)(in.payloadOff - in.dotSep);
    rem[0] === 1;
    rem[1] === 0;
    assert(rem[0] == 1);
    assert(rem[1] == 0);


    // Do not use V3, our base64 can start at an offset!
    signal bytes[MAX_BYTES] <== bits2partialB64DecodeV6(payload_bytes, MAX_BASE64)(
        bits <== in.payload,
        offset <== in.payloadOff
    );

    // log("Decoded base64:");
    // for (var i = 0; i < 10; i++) {
    //     log(bytes[i]);
    // }
    // log("END");

    // TODO: Handle the offset that was required for base64.
    signal aligned[MAX_BYTES] <== SliceFixedLenV2(MAX_BYTES, MAX_BYTES)(bytes, in.jsonAlign);

    JsonCheckKeyValue(MAX_BYTES, MAX_KEY, MAX_VALUE)(
        data <== aligned,
        key <== key,
        key_length <== key_length,
        value <== value
    );

    // TODO: Add the following checks:
    // - [x] Confirm we have a valid offset (based on the '.' separator)
    // - [x] Account for 0-2 bytes offset in the data we get (due to the block restriction in Base64Decode)
    // - [x] Make sure the character before the quote does not escape the quote and that we are at a starting quote
    //       NOTE: Only whitespace, comma and brackets are allowed.
    // - [x] Make sure the quote actually is a quote
    // - [x] Compare the key or copy it to output
    // - [ ] Make sure we have the ending quote (i.e. noone has truncated or extended the key)
    //       NOTE: Decided against this and allow value truncation. Value includes quotation marks, so this can be detected.
    // - [x] Make sure there are only allowed characters between key ending quote and value start: whitespaces and `:`
    // - [x] Copy the value to output (later we will want to be able to process it as a _sd array,
    //       but for that we might want a separate base64 decode)



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

/*
# NOTES on base64 optimization
- We don't need to decode the header.
- We don't need to prove that the input is valid base64
- All of our base64 input does not contain base64 padding and is padded using SHA256 padding.
  - Input MUST be followed by 0x80 (not part of the input) because due to byte alignment this cannot contain the big-endian u64 length.
  - After this byte we always get 0x00 bytes because the length is always < payload_bytes and the padding would be this way, too.
  - This is not proven by the ZK circuit but if this is not the case, the issuer would've had to sign in a non-spec compliant way.
- It should be possible to abuse this fact in a base64 lookup, as neither 0x80 nor 0x00 is valid base64, thus avoiding bounds checks.
  At least within a base64 block. The length will always fit into u32, otherwise the circuit would be gigantic.
- There should be even more opportunities, given that we need the base64 encoded a binary for computing sha256.
*/

// Configuration: MAX_PAYLOAD_BYTES, num_sd, sdbytes, path_depth
component main {public [value]} = SDJWT_ES256_SHA256_1claim(4096, 3, 200, 2);

