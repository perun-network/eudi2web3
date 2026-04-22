//! A helper for estimating which parts of a circuit has how many constraints.
//! This is very inacurate, ignores alias signals for the most part and is counting constraints
//! multiple times.

use std::{
    collections::{HashMap, hash_map::Entry},
    env::args,
    fs::File,
    io::{BufRead, BufReader},
};

use r1cs_file::{Constraint, R1csFile};

const BN_FS: usize = 32;
// const BLS_FS: usize = 48;

fn main() {
    let mut wirenames = vec![];

    let r1cs = args().skip(1).next().unwrap();
    eprintln!("Processing symbols");
    let syms = r1cs.replacen("r1cs", "sym", 1);
    let syms = File::open(&syms).unwrap();
    let syms = BufReader::new(syms);
    for line in syms.lines() {
        let line = line.unwrap();
        let mut cols = line.split(',');
        cols.next().unwrap();
        let wireid = cols.next().unwrap();
        // TODO: For more accurate results we should store all aliases, then decide during bucket
        // assignment which alias was most likely (based on shared prefixes). That way it should be
        // possible to assign a constraint to a specific component instead of counting which
        // signals touch the constraint (possibly using the wrong alias and thus missattributing).
        if wireid == "-1" {
            continue; // Alias to a different signal
        }
        cols.next().unwrap();
        let location = cols.next().unwrap();
        let wireid: usize = wireid.parse().unwrap();
        if wireid >= wirenames.len() {
            // Avoid too many resizes.
            wirenames.resize(wireid + 1000, location.to_owned());
        }
    }

    eprintln!("Decoding r1cs");
    let r1cs = File::open(&r1cs).unwrap();
    let r1cs: R1csFile<BN_FS> = R1csFile::read(r1cs).unwrap();

    let mut buckets = HashMap::new();

    println!("Total constraints: {}", r1cs.constraints.0.len());

    eprintln!("Buckets");
    for constraint in r1cs.constraints.0 {
        let Constraint(a, b, c) = constraint;
        let mut wires: Vec<_> = a
            .iter()
            .chain(b.iter())
            .chain(c.iter())
            .map(|(_, wire)| wire)
            .collect();
        wires.sort();
        wires.dedup();

        // TODO: For more accurate results we should dedup on the bucket level, otherwise we count one
        // constraint multiple times.
        for id in wires {
            let name = &wirenames[*id as usize];
            for (pos, _) in name.match_indices('.') {
                let n = &name[..pos];
                match buckets.entry(n) {
                    Entry::Occupied(mut e) => *e.get_mut() += 1u32,
                    Entry::Vacant(e) => {
                        e.insert(1u32);
                    }
                }
                // buckets.get(name[..pos])
            }
        }
    }

    eprintln!("Sorting buckets");
    let mut buckets: Vec<(&str, u32)> = buckets.into_iter().collect();
    buckets.sort_by_key(|(_, c)| *c);
    for (k, count) in buckets.into_iter().rev() {
        println!("{count:8} {k}");
    }
}
