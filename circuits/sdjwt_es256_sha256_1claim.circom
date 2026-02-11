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

template BEBits2Array(n, k) {
    // We could allow other sizes, but then it's not obvious what needs to be padded.
    assert(n%k == 0);

    signal input bits[n]; // binary
    signal output out[k];

    // Calculate the required size for Bits2Num (last one can be shorter).
    var size = (n+k-1)\k; // div_ceil

    // Create the components
    component b2n[k];
    for (var i = 0; i < k; i++) {
        b2n[i] = Bits2Num(size);
        for (var x = 0; x < size; x++) {
            b2n[i].in[size-1-x] <== bits[i*size+x];
        }
    }

    // Wire up the output
    for (var i = 0; i < k; i++) {
        out[i] <== b2n[i].out;
    }
}

template BEBits2Limbs {
    signal input bits[256]; // binary
    signal output out[6];

    component b2n[6];

    for (var i = 0; i < 6; i++) {
        b2n[i] = Bits2Num(43);
        for (var j = 0; j < 43; j++) {
            var bitPos = i * 43 + j;
            if (bitPos < 256) {
                // sha.out is most significant bit first. Reverse to obtain least significant bit first numeric interpretation
                b2n[i].in[j] <== bits[255 - bitPos];
            } else {
                b2n[i].in[j] <== 0;
            }
        }
        out[i] <== b2n[i].out;
    }
}

template SDJWT_ES256_SHA256_1claim(payload_bytes, num_sd, sdbytes, path_depth) {
    input SDJWT(payload_bytes, num_sd, sdbytes, path_depth) in;

    // Canary to detect when rust_witness doesn't have all inputs. Can be removed.
    signal output test <== 99;

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
