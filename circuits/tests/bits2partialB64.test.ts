import { wasm as wasm_tester } from "circom_tester";
import path from "path";

describe("bits2partialB64", () => {
    jest.setTimeout(5 * 60 * 1000) // 5 minutes

    let circuits: any[];
    const VERSIONS = 6;

    beforeAll(async () => {
        circuits = [];
        // Compile the circuits
        for (let v = 0; v < VERSIONS; v++) {
            circuits[v] = await wasm_tester(path.join(__dirname, "./test-circuits/bits2partialB64_" + (v + 1) + ".circom"), {
                recompile: true,
                include: path.join(__dirname, "../")
            })
        }
    });

    // Base64 of the bytes 100-1
    // [100-i for i in range(100)]
    // Then base64 encoded and truncated to the first 128 base64 bytes.
    //
    // Decoded and represented as hex:
    // 00: 64 63 62 61  60 5f 5e 5d   5c 5b 5a 59  58 57 56 55
    // 16: 54 53 52 51  50 4f 4e 4d   4c 4b 4a 49  48 47 46 45
    // 32: 44 43 42 41  40 3f 3e 3d   3c 3b 3a 39  38 37 36 35
    // 48: 34 33 32 31  30 2f 2e 2d   2c 2b 2a 29  28 27 26 25
    // 64: 24 23 22 21  20 1f 1e 1d   1c 1b 1a 19  18 17 16 15
    // 80: 14 13 12 11  10 0f 0e 0d   0c 0b 0a 09  08 07 06 05
    // 96:
    //
    // https://cyberchef.org/#recipe=From_Decimal('Comma',false)To_Base64('A-Za-z0-9-_')Head('Nothing%20(separate%20chars)',128)&input=MTAwLCA5OSwgOTgsIDk3LCA5NiwgOTUsIDk0LCA5MywgOTIsIDkxLCA5MCwgODksIDg4LCA4NywgODYsIDg1LCA4NCwgODMsIDgyLCA4MSwgODAsIDc5LCA3OCwgNzcsIDc2LCA3NSwgNzQsIDczLCA3MiwgNzEsIDcwLCA2OSwgNjgsIDY3LCA2NiwgNjUsIDY0LCA2MywgNjIsIDYxLCA2MCwgNTksIDU4LCA1NywgNTYsIDU1LCA1NCwgNTMsIDUyLCA1MSwgNTAsIDQ5LCA0OCwgNDcsIDQ2LCA0NSwgNDQsIDQzLCA0MiwgNDEsIDQwLCAzOSwgMzgsIDM3LCAzNiwgMzUsIDM0LCAzMywgMzIsIDMxLCAzMCwgMjksIDI4LCAyNywgMjYsIDI1LCAyNCwgMjMsIDIyLCAyMSwgMjAsIDE5LCAxOCwgMTcsIDE2LCAxNSwgMTQsIDEzLCAxMiwgMTEsIDEwLCA5LCA4LCA3LCA2LCA1LCA0LCAzLCAyLCAx
    const base64 = "ZGNiYWBfXl1cW1pZWFdWVVRTUlFQT05NTEtKSUhHRkVEQ0JBQD8-PTw7Ojk4NzY1NDMyMTAvLi0sKyopKCcmJSQjIiEgHx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYF";

    // First number is the offset in base64 where we want to read. It has to be a multiple of 4 (at least for the current implementations).
    // Second array is the expected output when reading 12 bytes starting from that location.
    //
    // The base64 decoded bytes are 100, 99, ...
    let cases = [
        [0, [100, 99, 98, 97, 96, 95, 94, 93, 92, 91, 90, 89]],
        // [3 * 4 / 3, [97, 96, 95, 94, 93, 92]],
        [42 * 4 / 3, [58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47]],
        // Test for reading beyond the base64 data. We expect 0 as a safe fallback,
        // given that 0 is also used for don't care when checking the value,
        // and it is the most sane value to use for data beyond the base64 end.
        [93 * 4 / 3, [7, 6, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0]],
    ];

    for (let v = 0; v < VERSIONS; v++) {
        for (let c = 0; c < cases.length; c++) {
            it("v" + (v + 1) + " should select " + cases[c][0] + " correctly", async () => {
                // Input: 8*100 bits (base64 encoded)
                // Intermediary: 8 bytes base64
                // Output: 6 bytes
                const witness = await circuits[v].calculateWitness({
                    bits: toBEBits(base64),
                    // offset: 42 * 4 / 3 // position is in base64, not the output bytes
                    offset: cases[c][0],
                });
                await circuits[v].checkConstraints(witness);
                await circuits[v].assertOut(witness, {
                    out: cases[c][1]
                });
            })
        }
    }

    for (let v = 0; v < VERSIONS; v++) {
        // Skip this test for V3, it does not allow base offsets and enforces that base64 blocks start at a multiple of 4.
        if (v == 2) continue;

        // No need to check offset 0, it is handled by the test case above.
        // To not blow up the number of tests we only test with a single offset.
        for (let o = 1; o < 4; o++) {

            it("v" + (v + 1) + " should correctly handle " + o + " byte offsets to the base64 start", async () => {
                const c = 1;
                const witness = await circuits[v].calculateWitness({
                    bits: toBEBits(".".repeat(o) + base64.substring(0, base64.length - o)),
                    offset: o + (cases[c][0] as number),
                })
                await circuits[v].checkConstraints(witness);
                await circuits[v].assertOut(witness, {
                    out: cases[c][1]
                });
            });
        }
    }
});

function toBEBits(bytes: string): number[] {
    const bits: number[] = [];
    for (const byte of bytes) {
        const code = byte.charCodeAt(0);
        for (let i = 7; i >= 0; i--) {  // big endian: MSB first
            bits.push((code >> i) & 1);
        }
    }
    return bits;
}
