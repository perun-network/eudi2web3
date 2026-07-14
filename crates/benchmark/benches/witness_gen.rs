use criterion::{Criterion, SamplingMode, criterion_group, criterion_main};
use eudi2web3::witness::{
    CircuitId,
    sha::{BitSignalVisitor, SHA256COMPRESSION_SIGNAL_COUNT, WitAssertEq, wit_sha256compression},
};
use num_bigint::BigInt;
use std::{fs::File, hint::black_box, io::Write, path::Path, process::Command, time::Duration};
use tempfile::tempdir;
use wtns_file::WtnsFile;

/*
const VP_TINY: &str = "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsicXNqNXkzMnV0M3V3MGJYeHFqUjE1WTJwcUxJMGdXYThjYkNuSm9RTUZ3VSJdLCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImkiLCJleHAiOjE4ODMwMDAwMDB9.pDAQ6qh5fSTNPYLHScZXtpsZZErn_yWE5BwFyWVM2E4rOXjRBS_DYZ0bc9gl30ORJzyfuc3khOygGQ50pZIqIA~WyJLZ01NZ3JkeVRaLXhaR1ZCdU02NUFBIiwgImdpdmVuX25hbWUiLCAiZm9vYmFyIl0~";

const VP: &str = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCIsICJ4NWMiOiBbIk1JSUMzekNDQW9XZ0F3SUJBZ0lVZjNsb2hUbURNQW1TL1lYL3E0aHFvUnlKQjU0d0NnWUlLb1pJemowRUF3SXdYREVlTUJ3R0ExVUVBd3dWVUVsRUlFbHpjM1ZsY2lCRFFTQXRJRlZVSURBeU1TMHdLd1lEVlFRS0RDUkZWVVJKSUZkaGJHeGxkQ0JTWldabGNtVnVZMlVnU1cxd2JHVnRaVzUwWVhScGIyNHhDekFKQmdOVkJBWVRBbFZVTUI0WERUSTFNRFF4TURFME16YzFNbG9YRFRJMk1EY3dOREUwTXpjMU1Wb3dVakVVTUJJR0ExVUVBd3dMVUVsRUlFUlRJQzBnTURFeExUQXJCZ05WQkFvTUpFVlZSRWtnVjJGc2JHVjBJRkpsWm1WeVpXNWpaU0JKYlhCc1pXMWxiblJoZEdsdmJqRUxNQWtHQTFVRUJoTUNWVlF3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVM3V0FBV3FQemUwVXMzejhwYWp5VlBXQlJtclJiQ2k1WDJzOUd2bHliUXl0d1R1bWNabmVqOUJrTGZBZ2xsb1g1dHYrTmdXZkRmZ3QvMDZzKzV0VjRsbzRJQkxUQ0NBU2t3SHdZRFZSMGpCQmd3Rm9BVVlzZVVSeWk5RDZJV0lLZWF3a21VUlBFQjA4Y3dHd1lEVlIwUkJCUXdFb0lRYVhOemRXVnlMbVYxWkdsM0xtUmxkakFXQmdOVkhTVUJBZjhFRERBS0JnZ3JnUUlDQUFBQkFqQkRCZ05WSFI4RVBEQTZNRGlnTnFBMGhqSm9kSFJ3Y3pvdkwzQnlaWEJ5YjJRdWNHdHBMbVYxWkdsM0xtUmxkaTlqY213dmNHbGtYME5CWDFWVVh6QXlMbU55YkRBZEJnTlZIUTRFRmdRVXFsL29weGtRbFl5MGxsYVRvUGJERS9teUVjRXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1GMEdBMVVkRWdSV01GU0dVbWgwZEhCek9pOHZaMmwwYUhWaUxtTnZiUzlsZFMxa2FXZHBkR0ZzTFdsa1pXNTBhWFI1TFhkaGJHeGxkQzloY21Ob2FYUmxZM1IxY21VdFlXNWtMWEpsWm1WeVpXNWpaUzFtY21GdFpYZHZjbXN3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQU5KVlNEc3FUM0lrR2NLV1dnU2V1YmtET2RpNS9VRTliMUdGL1g1ZlFSRmFBaUJwNXQ2dEhoOFh3RmhQc3R6T0hNb3B2QkQvR3dtczBSQVVnbVNuNmt1OEdnPT0iXX0.eyJfc2QiOiBbIjcyNE5lZjZfcHpYU2V5ZDFUSE9oSXBVX2Nrenc2bnNBRkNrSlhPUjJSRkkiLCAiTGtIb3J0RUROMmUtVnJxUDRwSFNHbUhGdXlMdWpRV1ZaY0dQR3ZuYjI1ayIsICJaRmVDTGlNTlgxaGZiaDduWklnMnNQNjNLa1B1TTRzclV6SUpCWUJwZE5vIiwgImtsMlJXcm5EanljbldSbEZpNmo2LUJtYXJvaFpSOWFoYm5wM0RJY1BXcGMiLCAidFR0U1RHMm44ZmhPTTEzQnk5cjk0RDJlQ1ZHbHFqOHFMcVh2akV6S0J4QSIsICJ3VXQ4WlRKNlRHTjVaY19sZVRHNmFWSVNZNDJVZWNBM3h5QmxnendIa19ZIiwgInhZaTdZU2NmVVhfWVowc0pjQm5uTWIwQ0toQXR6M25EdE5CMGh2M3N2VjQiLCAieU5zTlBpaDdyN2dpSWE1aGhLZ1Bxc3A5aUNCWXhHa1JCRW51WksyOFZoSSJdLCAiaXNzIjogImh0dHBzOi8vYmFja2VuZC5pc3N1ZXIuZXVkaXcuZGV2IiwgImlhdCI6IDE3NzU2MDI4MDAsICJleHAiOiAxNzgzMzc4ODAwLCAidmN0IjogInVybjpldWRpOnBpZDoxIiwgInN0YXR1cyI6IHsic3RhdHVzX2xpc3QiOiB7ImlkeCI6IDcyNTcsICJ1cmkiOiAiaHR0cHM6Ly9pc3N1ZXIuZXVkaXcuZGV2L3Rva2VuX3N0YXR1c19saXN0L0ZDL3VybjpldWRpOnBpZDoxL2Q4NDBjNTY4LTJlMzYtNGFhMC04Mjg5LWIyOWZkMWU5MWMwZiJ9fSwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIl91TUJvU2pqMG5HX0tJSnJCR1VJcG8xN3lqLWJ5Y1djSzFsSW9VckcxdXciLCAieSI6ICI4WTk3YWRaRGMxNlJ6X2UwOHJ0czlFZ2s3MVNJOFJNSERsOElYM3JGMFhNIn19fQ._3KRjhJ-a2MYsl00RVqGJ_X1dzTY-p2vEOzpqXBTk7UcKZYlfq96FKy-4nMIlSDuXwsd5dNwk3Rwouc7-WOh6w~WyJJcTByR0ZqTVFjeDZNZUhZVVJXempBIiwgImdpdmVuX25hbWUiLCAiZm9vYmFyOCJd~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJzZF9oYXNoIjoic1NJZmZ1V25VQllpWUl3QWJBdXJMSzF0eTd1VFdmVEZiV21UTW8zUUJVYyIsImF1ZCI6Ing1MDlfaGFzaDo0alB0Q1prUDF1NHd6OEJ3UlMtZmJEQU4tYW1TRTQ5Q010bWdtUXhUTWIwIiwibm9uY2UiOiJDY0JKTUEyMTFDMjVsQmtDNVNvQk42eUhldkZpempPTCIsImlhdCI6MTc3NjkzNDc2MX0.VADcrT6DX5T3z-zIkAUj7Ux3tU0ylfqMzejoD4bI-h8rNeOuXP9R4aVX_qLlmVqOfvs1uiIQu5PIpoZfwWfWlA";

fn bench(c: &mut Criterion) {
    // We are started in the crates/benchmark directory, so we have to set PWD to the workspace root
    // to find the zkeys.
    std::env::set_current_dir(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap(),
    )
    .unwrap();
    let circuits = eudi2web3::witness::get_circuits();

    let mut group = c.benchmark_group("witness_gen");

    for (id, e) in &circuits {
        let Some(params) = e.params else {
            continue;
        };
        // Currently way too slow to be useful.
        if id.circuit == "small" {
            continue;
        }
        let vp = match params.payload {
            // Bounds are not accurate. Doesn't really matter which credential we use, as the
            // circuit always has to handle the worst-case anyways.
            2000.. => VP,
            _ => VP_TINY,
        };

        group
            .sample_size(10)
            .bench_with_input(format!("{id}/w2c2"), e, |b, e| {
                let input =
                    presentation2input(e.params.expect("circuit to have params"), vp).unwrap();
                let input = vec![
                    ("passthrough".to_owned(), vec![BigInt::ZERO; 2]),
                    ("in".to_owned(), input.input),
                    ("value".to_owned(), input.value),
                ];
                b.iter(|| (e.compute_witness)(black_box(input.clone())))
            });
    }
}
*/

fn sha_only(c: &mut Criterion) {
    // We are started in the crates/benchmark directory, so we have to set PWD to the workspace root
    // to find the zkeys.
    std::env::set_current_dir(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap(),
    )
    .unwrap();
    let circuits = eudi2web3::witness::get_circuits();
    let circuit = &circuits[&CircuitId {
        curve: "bn254".to_owned(),
        circuit: "only_sha".to_owned(),
        contributions: 1,
    }];

    let tmp_dir = tempdir().unwrap();
    let input_path = tmp_dir.path().join("input.json");
    let output_path = tmp_dir.path().join("output.wtns");

    let mut f = std::fs::File::create(&input_path).unwrap();
    write!(f, r#"{{"in":["#).unwrap();
    for _ in 0..511 {
        write!(f, r#""0","#).unwrap();
    }
    write!(f, r#""0""#).unwrap();
    write!(f, "]}}").unwrap();
    f.sync_all().unwrap();
    drop(f);

    let mut g = c.benchmark_group("only_sha");

    g.sample_size(10)
        .sampling_mode(SamplingMode::Flat)
        .bench_function("w2c2", |b| {
            b.iter(|| (circuit.compute_witness)(vec![("in".to_owned(), vec![BigInt::ZERO; 512])]))
        });
    g.bench_function("cpp_exe", |b| {
        b.iter(|| {
            let success = Command::new("zkey/bn254/only_sha_cpp/only_sha")
                .arg(&input_path)
                .arg(&output_path)
                .spawn()
                .unwrap()
                .wait()
                .unwrap()
                .success();
            assert!(success);
        })
    });
    g.sample_size(10)
        .sampling_mode(SamplingMode::Flat)
        .measurement_time(Duration::from_secs(30))
        .bench_function("snarkjs", |b| {
            b.iter(|| {
                let success = Command::new("snarkjs")
                    .arg("wc")
                    .arg("zkey/bn254/only_sha_js/only_sha.wasm")
                    .arg(&input_path)
                    .arg(&output_path)
                    .spawn()
                    .unwrap()
                    .wait()
                    .unwrap()
                    .success();
                assert!(success);
            })
        });
    // c.bench_function("fib 20", |b| b.iter(|| fibonacci(black_box(20))));
}

fn sha_compression(c: &mut Criterion) {
    let tmp_dir = tempdir().unwrap();
    let input_path = tmp_dir.path().join("input.json");
    let output_path = tmp_dir.path().join("output.wtns");

    let mut f = std::fs::File::create(&input_path).unwrap();
    write!(f, r#"{{"in":["#).unwrap();
    write!(f, r#""1","#).unwrap();
    for _ in 1..511 {
        write!(f, r#""0","#).unwrap();
    }
    write!(f, r#""0""#).unwrap();
    write!(f, "]}}").unwrap();
    f.sync_all().unwrap();
    drop(f);

    // "" (padded)
    let input = [1 << 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let success = Command::new("zkey/bn254/only_sha_cpp/only_sha")
        .arg(&input_path)
        .arg(&output_path)
        .spawn()
        .unwrap()
        .wait()
        .unwrap()
        .success();
    assert!(success);

    // Read back the witness values
    let f = File::open(&output_path).unwrap();
    let wtns: WtnsFile<32> = WtnsFile::read(f).unwrap();

    let wtns: Vec<BigInt> = wtns
        .witness
        .0
        .into_iter()
        .map(|s| BigInt::from_bytes_le(num_bigint::Sign::Plus, s.as_bytes()))
        .collect();
    let start = 1806;

    // End of preparation to get the expected witness array.

    let mut g = c.benchmark_group("sha_compression");

    g.sample_size(50).bench_function("assert_eq", |b| {
        b.iter(|| wit_sha256compression(input, &mut WitAssertEq(&wtns[start..])))
    });
    g.bench_function("nop", |b| {
        b.iter(|| wit_sha256compression(input, &mut NopSignalVisitor))
    });
    g.bench_function("blackbox", |b| {
        b.iter(|| wit_sha256compression(input, &mut BlackboxSignalVisitor))
    });
    g.bench_function("collect_bigint", |b| {
        b.iter(|| {
            wit_sha256compression(
                input,
                &mut BigIntCollectSignalVisitor(vec![BigInt::ZERO; SHA256COMPRESSION_SIGNAL_COUNT]),
            );
        })
    });
    assert_eq!(SHA256COMPRESSION_SIGNAL_COUNT.div_ceil(64), 480);
    g.bench_function("collect_bits", |b| {
        b.iter(|| wit_sha256compression(input, &mut BitCollectSignalVisitor(vec![0_u64; 480])))
    });
}

struct NopSignalVisitor;
impl BitSignalVisitor for NopSignalVisitor {
    fn visit_bool(&mut self, _: usize, _: bool) {}
    fn visit_u32(&mut self, _: usize, _: u32) {}
}

struct BlackboxSignalVisitor;
impl BitSignalVisitor for BlackboxSignalVisitor {
    fn visit_bool(&mut self, bitpos: usize, value: bool) {
        black_box(bitpos);
        black_box(value);
    }
    fn visit_u32(&mut self, bitpos: usize, value: u32) {
        black_box(bitpos);
        black_box(value);
    }
}

struct BigIntCollectSignalVisitor(Vec<BigInt>);
impl BitSignalVisitor for BigIntCollectSignalVisitor {
    fn visit_bool(&mut self, bitpos: usize, value: bool) {
        if value {
            self.0[bitpos] = BigInt::from(1);
        }
    }
}
struct BitCollectSignalVisitor(Vec<u64>);
impl BitSignalVisitor for BitCollectSignalVisitor {
    fn visit_bool(&mut self, bitpos: usize, value: bool) {
        self.0[bitpos / 64] |= (value as u64) << (bitpos % 64)
    }
}

// The function we'd need to replace (note that 100 may change on circuit changes).
// void Sha256compression_100_run(uint ctx_index,Circom_CalcWit* ctx);

criterion_group!(benches, sha_only, sha_compression);
criterion_main!(benches);
