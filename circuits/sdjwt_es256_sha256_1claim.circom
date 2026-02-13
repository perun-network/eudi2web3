pragma circom 2.2.3;

include "circom-ecdsa-p256/circuits/ecdsa.circom";
include "zk-email-verify/packages/circuits/lib/sha.circom";
include "circomlib/circuits/bitify.circom";
include "bits2partialB64.circom";

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

    // Index into payload where the interesting data starts. Must point to the start of a block in the body,
    // even though the offset is from the start of header (all base64 encoded, including the separating dot).
    // TODO: We may want to change this at some point.
    // @type: u64
    signal payloadOff;
}


template SDJWT_ES256_SHA256_1claim(payload_bytes, num_sd, sdbytes, path_depth) {
    input SDJWT(payload_bytes, num_sd, sdbytes, path_depth) in;

    // Canary to detect when rust_witness doesn't have all inputs. Can be removed.
    signal output test <== 99;

    /*
    // Compute hash of JWT header+body
    // TODO: I don't think this verifies if the padding is correct, which could be an attack vector.
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
    signal hash[6] <== BEBits2Limbs()(hash_bin);
    var valid = ECDSAVerifyNoPubkeyCheck(43, 6)(
        r <== in.sig.r, 
        s <== in.sig.s,
        pubkey <== in.pk,
        msghash <== hash
    );
    assert(valid);
    valid === 1;
    */

    // We are looking for a json key-value pair: `"key":.*[,}\]]` inside the base64.
    // The base64 decoder we currently have is not sha2 padding aware, so we should
    // stay in-bounds or we need special handling for padding.
    // We can get various positions as input.
    // Base64: 012345 012345 012345 012345
    // Bytes:  01234501 23450123 45012345
    // base64pos = bytespos * 4/3
    // 0*4/3 = 0
    // 1*4/3 = 4/3 = 1
    // 2*4/3 = 8/3 = 2
    // 3*4/3 = 12/3 = 4
    var max_kv_b64_len = 64;
    // PERFORMANCE: This feels very inefficient. I'm trying out two different variants to see which ones has fewer constraints:
    // 1) A single Multiplexer with a multi-signal output
    //    - 64/1024 bytes relevant for base64 => 70386 constraints, 78067 wires, 274047 labels
    // 2) One multiplexer byte, which is what the eudi-web3-bridge project used.
    // TODO: For now both implementations assume they are in-bounds.
    
    // Implementatino for 1)
    // Convert bits to u8.
    // PERFORMANCE: It likely makes a difference whether we do this for all inputs and then multiplex on fewer signals
    //              or if we multiplex on 8x the amount of inputs and then convert to bytes.
    //              The first one sounds faster, but I have not benchmarked it.
    // signal b64[payload_bytes];
    // component b64_b2n[payload_bytes];
    // for (var i = 0; i < payload_bytes; i++) {
    //     b64_b2n[i] = Bits2Num(8);
    //     for (var b = 0; b < 8; b++) {
    //         // Bits2Num expects little-endian
    //         b64_b2n[i].in[7-b] <== in.payload[8*i+b];
    //     }
    //     b64_b2n[i].out ==> b64[i];
    // }
    // log("B64 input:");
    // for (var i = 0; i < max_kv_b64_len; i++) {
    //     log(b64[in.payloadOff + i]);
    // }
    // // TODO: in.payload is in binary, so we'll have to build base64 signals first ...
    // // NOTE: This implementation has problems if the selection end is after payload_bytes ends.
    // component mul = Multiplexer(max_kv_b64_len, payload_bytes-max_kv_b64_len);
    // for (var i = 0; i < payload_bytes-max_kv_b64_len; i++) {
    //     for (var o = 0; o < max_kv_b64_len; o++) {
    //         mul.inp[i][o] <== b64[i+o];
    //     }
    // }
    // mul.sel <== in.payloadOff;
    // log("Mux output:");
    // for (var i = 0; i < max_kv_b64_len; i++) {
    //     log(mul.out[i]);
    // }
    // assert(max_kv_b64_len % 4 == 0);
    // component dec = Base64Decode(max_kv_b64_len/4*3);
    // dec.in <== mul.out;

    // Do not use V3, out base64 can start at an offset!
    signal bytes[max_kv_b64_len/4*3] <== bits2partialB64DecodeV6(payload_bytes, max_kv_b64_len)(
        bits <== in.payload,
        offset <== in.payloadOff
    );

    log("Decoded base64:");
    for (var i = 0; i < max_kv_b64_len/4*3; i++) {
        log(bytes[i]);
    }
    log("END");

    // TODO: Add the following checks:
    // - [ ] Confirm we have a valid offset (based on the '.' separator)
    // - [ ] Account for 0-2 bytes offset in the data we get (due to the block restriction in Base64Decode)
    // - [ ] Make sure the character before the quote does not escape the quote and that we are at a starting quote
    //       NOTE: Only whitespace, comma and brackets are allowed.
    // - [ ] Make sure the quote actually is a quote
    // - [ ] Compare the key or copy it to output
    // - [ ] Make sure we have the ending quote (i.e. noone has truncated or extended the key)
    // - [ ] Make sure there are only allowed characters between key ending quote and value start: whitespaces and `:`
    // - [ ] Copy the value to output (later we will want to be able to process it as a _sd array,
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

component main = SDJWT_ES256_SHA256_1claim(1024, 3, 200, 2);
