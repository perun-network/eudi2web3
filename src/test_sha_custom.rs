use std::{ops::Shr, time::Instant};

use num_bigint::BigInt;

use crate::witness::CircuitId;

#[test]
fn explore_custom_sha_gen() {
    let circuits = crate::witness::get_circuits();
    let circuit = &circuits[&CircuitId {
        curve: "bn254".to_owned(),
        circuit: "only_sha".to_owned(),
        contributions: 1,
    }];

    let mut input = vec![BigInt::ZERO; 512];
    input[0] = BigInt::from(1_u64);
    let wit = (circuit.compute_witness)(vec![("in".to_owned(), input)]);

    let t0 = Instant::now();

    let start = 1806;

    // Note: This may change with different circom versions or tiny circuit changes
    let a1_start = start;
    let e1_start = a1_start + 64 * 32;
    let w16_start = e1_start + 64 * 32;
    let fsum_start = w16_start + (64 - 16) * 32; // Final sum
    let sig0_start = fsum_start + 8;
    let suma_start = sig0_start + (64 - 16) * 130;
    let sume_start = suma_start + 64 * 65;
    let t1_start = sume_start + 64;
    let t2_start = t1_start + 64 * 99;
    let end = t2_start + 64 * 129;
    assert_eq!(end - start, 30696);

    let hin = H;

    let mut w = [0_u32; 64];
    // TODO: Fill first 16 entries with the input chunk
    w[0] = 1 << 31;

    for i in 0..(64 - 16) {
        // NOTE: Naming schema in the circuit is backwards: w2 there is w14 here (16-x).
        let w1 = w[i + 1];
        let w14 = w[i + 14];

        let sig0_b = w1.rotate_right(18);
        let sig0_c = w1.shr(3);
        let sig0 = w1.rotate_right(7) ^ sig0_b ^ sig0_c;

        let sig1_b = w14.rotate_right(19);
        let sig1_c = w14.shr(10);
        let sig1 = w14.rotate_right(17) ^ sig1_b ^ sig1_c;

        // Normally I would stay in u32, but we need to provide the overflow bits to the witness,
        // even though they are meaningless in terms of sha256 validity. This is because the circuit
        // just uses BinSum, which doesn't do implicit wrapping.
        let sum = (w[i] as u64) + (sig0 as u64) + (w[i + 9] as u64) + (sig1 as u64);
        w[i + 16] = sum as u32; // SHA256 wants wrapping addition.

        spread_check(&wit[w16_start + 32 * i..], w[i + 16]);

        spread_check(&wit[sig0_start + 130 * i..], sig0); // sigma0.out
        spread_check(&wit[sig0_start + 130 * i + 32..], sig0_b & sig0_c); // sigma0.xor3.mid
        spread_check(&wit[sig0_start + 130 * i + 64..], sig1); // sigma1.out
        spread_check(&wit[sig0_start + 130 * i + 96..], sig1_b & sig1_c); // sigma1.xor3.mid
        assert_eq!(wit[sig0_start + 130 * i + 128], bit_signal64(sum, 32)); // sum.out[32]
        assert_eq!(wit[sig0_start + 130 * i + 129], bit_signal64(sum, 33)); // sum.out[33]
    }

    let mut a = H[0];
    let mut b = H[1];
    let mut c = H[2];
    let mut d = H[3];
    let mut e = H[4];
    let mut f = H[5];
    let mut g = H[6];
    let mut h = H[7];

    // PERFORMANCE: If the compiler is good it, it unrolls this loop.
    for i in 0..64 {
        let s0_b = a.rotate_right(13);
        let s0_c = a.rotate_right(22);
        let s0 = a.rotate_right(2) ^ s0_b ^ s0_c;

        let s1_b = e.rotate_right(11);
        let s1_c = e.rotate_right(25);
        let s1 = e.rotate_right(6) ^ s1_b ^ s1_c;

        let choice = (e & f) ^ (!e & g);
        let majority = (a & b) ^ (a & c) ^ (b & c);

        // Doesn't exist in SHA256, this is an intermediate of the Maj_t template.
        // Needs to be calculated here, as the variables are written below. We technically could
        // compute this in the end and use c and d, but that's more confusing.
        let maj_mid = b & c;

        // Normally I would stay in u32, but we need to provide the overflow bits to the witness,
        // even though they are meaningless in terms of sha256 validity. This is because the circuit
        // just uses BinSum, which doesn't do implicit wrapping.
        let temp1 = (h as u64) + (s1 as u64) + (choice as u64) + (K[i] as u64) + (w[i] as u64);
        let (temp2, temp2_overflow) = s0.overflowing_add(majority);

        h = g;
        g = f;
        f = e;
        let (_e, e_overflow) = d.overflowing_add(temp1 as u32);
        e = _e;
        d = c;
        c = b;
        b = a;
        let (_a, a_overflow) = (temp1 as u32).overflowing_add(temp2);
        a = _a;

        // The others have been optimized away be circom.
        spread_check(&wit[a1_start + 32 * i..], a);
        spread_check(&wit[e1_start + 32 * i..], e);

        assert_eq!(wit[suma_start + 65 * i], bool_signal(a_overflow)); // out[32]
        spread_check(&wit[suma_start + 65 * i + 1..], temp1 as u32); // in[0] == t1.out
        spread_check(&wit[suma_start + 65 * i + 33..], temp2); // in[1] == t2.out

        assert_eq!(wit[sume_start + i], bool_signal(e_overflow)); // out[32]

        spread_check(&wit[t1_start + 99 * i..], s1); // bigsigma1.out
        spread_check(&wit[t1_start + 99 * i + 32..], s1_b & s1_c); // bigsigma1.xor3.mid
        spread_check(&wit[t1_start + 99 * i + 64..], choice); // ch.out
        assert_eq!(wit[t1_start + 99 * i + 96], bit_signal64(temp1, 32)); // sum.out[32]
        assert_eq!(wit[t1_start + 99 * i + 97], bit_signal64(temp1, 33)); // sum.out[33]
        assert_eq!(wit[t1_start + 99 * i + 98], bit_signal64(temp1, 34)); // sum.out[34]

        spread_check(&wit[t2_start + 129 * i..], s0); // bigsigma0.out
        spread_check(&wit[t2_start + 129 * i + 32..], s0_b & s0_c); // bigsigma0.xor3.mid
        spread_check(&wit[t2_start + 129 * i + 64..], majority); // maj.out
        spread_check(&wit[t2_start + 129 * i + 96..], maj_mid); // maj.mid
        assert_eq!(wit[t2_start + 129 * i + 128], bool_signal(temp2_overflow)); // sum.out[32]
    }

    for (i, v) in [a, b, c, d, e, f, g, h].into_iter().enumerate() {
        assert_eq!(
            wit[fsum_start + i],
            bool_signal(hin[i].overflowing_add(v).1)
        );
    }

    println!("Elapsed: {:?}", t0.elapsed());
}

#[track_caller]
fn spread_check(wit: &[BigInt], value: u32) {
    // let mut sum = 0;
    // for b in 0..32 {
    //     sum += wit[b].to_u64().unwrap() << b;
    // }
    // dbg!(sum);

    for b in 0..32 {
        assert_eq!(wit[b], bit_signal32(value, b));
    }
}
fn bit_signal64(value: u64, bit: usize) -> BigInt {
    bool_signal((value >> bit & 1) > 0)
}
fn bit_signal32(value: u32, bit: usize) -> BigInt {
    bool_signal((value >> bit & 1) > 0)
}
fn bool_signal(value: bool) -> BigInt {
    if value {
        BigInt::from(1_u64)
    } else {
        BigInt::ZERO
    }
}

const H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
