use aiken/primitive/bytearray
use ak_381/groth16.{Proof, SnarkVerificationKey, groth_verify}
use cardano/transaction.{OutputReference, Transaction}

pub type Redeemer {
  // Groth16 proof
  proof: Proof,
  // Value of the extracted claim (public input)
  value: ByteArray,
}

fn bytes_to_ints(b: ByteArray, size: Int) -> List<Int> {
  when bytearray.length(b) == 0 is {
    True -> []
    False ->
      [
        bytearray.to_int_big_endian(bytearray.slice(b, 0, size)),
        ..bytes_to_ints(
          bytearray.slice(b, size, bytearray.length(b) - size),
          size,
        )
      ]
  }
}

validator eudi2web3_demo(vk: SnarkVerificationKey) {
  spend(
    _datum: Option<Data>,
    redeemer: Redeemer,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    // PERFORMANCE: We probably want to compress multiple bytes into a single signal (in circuit and here),
    // which is why I added the size argument.
    if groth_verify(vk, redeemer.proof, bytes_to_ints(redeemer.value, 1)) {
      True
    } else {
      fail
    }
  }

  else(_) {
    fail
  }
}
