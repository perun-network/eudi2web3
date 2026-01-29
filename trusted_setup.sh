#!/bin/bash
# Performs the trusted setup on the most recently compiled circuits

newestr1cs=$(ls -t target/{debug,release}/build/eudi2web3*/out/circom/*.r1cs | head -n1)
dir=$(dirname "$newestr1cs")
circuits=$(ls $dir/*.r1cs)

# Maximum circuit size: 2^$size
size=12
# curve="bn128"
curve="bls12-381"

pot="zkey/pot$size.ptau"

header() {
    echo -e "\x1b[1;94m$@\x1b[0m"
}

if [ ! -d "zkey" ]; then
    mkdir zkey
fi

if [ ! -f "$pot" ]; then
    header ptau
    snarkjs powersoftau new "$curve" "$size" "$pot" -v
    
    # # Commented out to see if the first command is enough if we don't actually have a distributed trust setup
    # header ptau contribution 1/1
    # snarkjs powersoftau contribute zkey/pot12.ptau zkey/pot12.ptau --name="First contribution" -v
    
    header ptau prepare phase2
    snarkjs powersoftau prepare phase2 "$pot" "$pot" -v
fi

for file in $circuits; do
  name=$(basename $file .r1cs)
  zkey="zkey/$name.zkey"

  header "$name" setup
  snarkjs groth16 setup "$file" "$pot" "$zkey"

  # Let's see if this is needed.
  # header "$name" contribution 1/1
  # snarkjs zkey contribute "$zkey" "$zkey" --name="1st Contributor Name" -v
  
  header "$name" export
  snarkjs zkey export verificationkey "$zkey" "zkey/${name}_vkey.json"
done

