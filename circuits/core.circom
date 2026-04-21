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
    // @type: u64
    signal payloadOff;
    // Value between 0 and 2 to go from base64 block alignment to the json start (character before quote)
    signal jsonAlign;
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

bus SDJWT(payload_bytes, ndisclosures, sdbytes, path_depth) {
    // @type: u128
    signal pk[2][6];                     // Issuer public key
    Signature sig;                                  // Part 1.3
    // @type: binary
    // Format: Padded according to sha2 spec, might not use all blocks.
    signal payload[payload_bytes*8];       // Part 1.(1+2):    base64(jwt_header) + '.' + base64(jwt_body)
    // @type: u64
    signal payloadLength;
    Disclosure(sdbytes) disclosures[ndisclosures];        // Part 2-n:        base64(json(disclosure_entry))

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
    // @type: u64
    signal distance2quote;
}


template Core(header, payload_bytes, max_sd_entries, disclosures, sdbytes, path_depth, do_crypto) {
    // Including the '.' separator, before base64 decoding
    var MAX_KEY = 10;           // Maximum length of the claim's key name (only one segment for now)
    var MAX_VALUE_SIGNALS = 2;  // Maximum length of the claim value we're interested in (output)
    var BYTES_PER_SIGNAL = 31;  // One signal can store 31 bytes.

    // TODO: Strictly speaking this should be based on key+value, which might be larger.
    // Header: `_"_sd": [`
    // Per Entry: `"<43-characters", `
    // Base64 alignment: 3
    var MAX_BYTES = 9 + max_sd_entries * 47 + 3;
    MAX_BYTES = MAX_BYTES + (3-MAX_BYTES%3)%3; // Round up to multiple of 3

    // `_"KEY": VALUE`
    // Base64 alignment: 3
    var MAX_BYTES_LAST = 5 + MAX_KEY + MAX_VALUE_SIGNALS * BYTES_PER_SIGNAL + 3;
    MAX_BYTES_LAST = MAX_BYTES_LAST + (3-MAX_BYTES_LAST%3)%3; // Round up to multiple of 3

    var MAX_VALUE = MAX_VALUE_SIGNALS * BYTES_PER_SIGNAL;

    input SDJWT(payload_bytes, disclosures, sdbytes, path_depth) in;
    signal input value[MAX_VALUE]; // 0-padded
    // Big endian, aligned to the LSB
    signal output value_compressed[MAX_VALUE_SIGNALS]; // Compressed representation for the verifier

    // Canary to detect when rust_witness doesn't have all inputs. Can be removed.
    // signal output test <== 99;

    var key[MAX_KEY] = [103, 105, 118, 101, 110, 95, 110, 97, 109, 101]; // "given_name"
    var key_length = 10;
    // var key[MAX_KEY] = [105, 115, 115, 0, 0, 0, 0, 0, 0, 0]; // "iss"
    // var key_length = 3;

    assert(MAX_BYTES % 3 == 0);
    var MAX_BASE64 = MAX_BYTES / 3 * 4;
    assert(MAX_BYTES_LAST % 3 == 0);
    var MAX_SD_BASE64 = MAX_BYTES_LAST / 3 * 4;

    if (do_crypto != 0) {
        // Compute hash of JWT header+body
        // TODO: I don't think this verifies if the padding is correct, which could be an attack vector.
        // For payload_bytes=1024:   524.563 constraints (approx.)
        // For payload_bytes=2048: 1.049.364 constraints (approx.)
        // For payload_bytes=4096: 2.098.965 constraints (approx.)
        signal hash_bin0[256] <== Sha256General(payload_bytes*8)(
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
        signal hash0[6] <== BEBits2Limbs()(hash_bin0);
        var valid = ecdsa__ECDSAVerifyNoPubkeyCheck(43, 6)(
            r <== in.sig.r, 
            s <== in.sig.s,
            pubkey <== in.pk,
            msghash <== hash0
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
    assert(in.dotSep < header);
    component dotCheck = Multiplexer(1,header);
    for (var i = 0; i < header; i++) {
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

    // PERFORMANCE: These two functions are pretty similar. We could try to write one that can do both.
    // We can't just use JsonCheckKeyValue because it outputs the entire array (even more wasteful) and
    // we can't just use the SD one because it has a hard coded key (simpler if only that'd be needed).
    // But: We need both (with the exception of the last one), so we could try to combine them to reduce
    // the constraint count. I've left them separate for now because it is simpler and so that the
    // dfiference is measurable.
    
    // For now let's start with a hard coded SD
    signal sd[43] <== JsonGetSDEntry(MAX_BYTES)(
        data <== aligned,
        distance2quote <== in.distance2quote
    );
    component sdb64 = Base64Decode(32);
    for (var i = 0; i < 43; i++) {
        sdb64.in[i] <== sd[i];
    }
    sdb64.in[43] <== 61; // '='

    if (do_crypto != 0) {
        // Compute hash of JWT header+body
        // TODO: I don't think this verifies if the padding is correct, which could be an attack vector.
        // For payload_bytes=1024:   524.563 constraints (approx.)
        // For payload_bytes=2048: 1.049.364 constraints (approx.)
        // For payload_bytes=4096: 2.098.965 constraints (approx.)
        signal hash_bin1[256] <== Sha256General(sdbytes*8)(
            paddedIn <== in.disclosures[0].data,
            paddedInLength <== in.disclosures[0].length
        );

        // Check if hash matches
        for (var i = 0; i < 32; i++) {
            var sum = hash_bin1[8*i] * 128
                + hash_bin1[8*i+1] * 64
                + hash_bin1[8*i+2] * 32
                + hash_bin1[8*i+3] * 16
                + hash_bin1[8*i+4] * 8
                + hash_bin1[8*i+5] * 4
                + hash_bin1[8*i+6] * 2
                + hash_bin1[8*i+7];
            sdb64.out[i] === sum;
            assert(sdb64.out[i] == sum);
        }
    }

    // TODO: Check key

    // Extract the value
    // Here we can use V3 because we're always properly aligned to base64 blocks.
    signal bytes2[MAX_BYTES_LAST] <== bits2partialB64DecodeV3(sdbytes, MAX_SD_BASE64)(
        bits <== in.disclosures[0].data,
        offset <== in.disclosures[0].payloadOff
    );
    signal aligned2[MAX_BYTES_LAST] <== SliceFixedLenV2(MAX_BYTES_LAST, MAX_BYTES_LAST)(bytes2, in.disclosures[0].jsonAlign);
    JsonCheckKeyValue(MAX_BYTES_LAST, MAX_KEY, MAX_VALUE)(
        data <== aligned2,
        key <== key,
        key_length <== key_length,
        value <== value,
        sep <== 44 // ','
        // sep <== 58 // ':'
    );

    value_compressed[0] <== 1;
    value_compressed[1] <== 1;

    // Compress value for more compact verification keys and proofs.
    //for (var s = 0; s < MAX_VALUE_SIGNALS; s++) {
        // var sum = 0;
        // for (var i = 0; i < BYTES_PER_SIGNAL; i++) {
        //     var factor = 1 << (8*(BYTES_PER_SIGNAL-i-1));
        //     sum += value[BYTES_PER_SIGNAL*s + i] * factor;
        // }
        // value_compressed[s] <== sum;

        // Alternative implementation that avoids linear combination detection and an ICE in circom.
        //assert(BYTES_PER_SIGNAL == 31);
        // value_compressed[s] <== 
            // value[31*s + 30] * (1 << (8*0));
            //value[31*s + 29] * (1 << (8*1)) + 
            //value[31*s + 28] * (1 << (8*2)) + 
            //value[31*s + 27] * (1 << (8*3)) + 
            //value[31*s + 26] * (1 << (8*4)) + 
            //value[31*s + 25] * (1 << (8*5)) + 
            //value[31*s + 24] * (1 << (8*6)) + 
            //value[31*s + 23] * (1 << (8*7)) + 
            //value[31*s + 22] * (1 << (8*8)) + 
            //value[31*s + 21] * (1 << (8*9)) + 
            //value[31*s + 20] * (1 << (8*10)) + 
            //value[31*s + 19] * (1 << (8*11)) + 
            //value[31*s + 18] * (1 << (8*12)) + 
            //value[31*s + 17] * (1 << (8*13)) + 
            //value[31*s + 16] * (1 << (8*14)) + 
            //value[31*s + 15] * (1 << (8*15)) + 
            //value[31*s + 14] * (1 << (8*16)) + 
            //value[31*s + 13] * (1 << (8*17)) + 
            //value[31*s + 12] * (1 << (8*18)) + 
            //value[31*s + 11] * (1 << (8*19)) + 
            //value[31*s + 10] * (1 << (8*20)) + 
            // value[31*s + 9] * (1 << (8*21)) + 
            // value[31*s + 8] * (1 << (8*22)) + 
            // value[31*s + 7] * (1 << (8*23)) + 
            // value[31*s + 6] * (1 << (8*24)) + 
            // value[31*s + 5] * (1 << (8*25)) + 
            // value[31*s + 4] * (1 << (8*26)) + 
            // value[31*s + 3] * (1 << (8*27)) + 
            // value[31*s + 2] * (1 << (8*28)) + 
            // value[31*s + 1] * (1 << (8*29)) + 
            // value[31*s + 0] * (1 << (8*30));
    //}

    // TODO: Make the circuit flexible and allow all of the following:
    // - No SD (claim direct in root object)
    // - Value is directly in sd entry (shown above)
    // - Value is an object in sd entry

    /*
a pre-defined scope value. See Section 5.5 for more details.
response_mode:
    JsonCheckKeyValue(MAX_BYTES, MAX_KEY, MAX_VALUE)(
        data <== aligned,
        key <== key,
        key_length <== key_length,
        value <== value,
        sep <== 58 // ':'
    );
    */

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

