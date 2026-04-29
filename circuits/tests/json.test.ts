import { wasm as wasm_tester } from "circom_tester";
import path from "path";

describe("JsonGetValue", () => {
    jest.setTimeout(5 * 60 * 1000) // 5 minutes

    let circuit: any;

    beforeAll(async () => {
        // Compile the circuit
        circuit = await wasm_tester(path.join(__dirname, "./test-circuits/jsonCheckKeyValue.circom"), {
            recompile: true,
            include: path.join(__dirname, "../")
        })
    });

    // NOTE: data does not need to be a complete json, but it must have exactly 1 character before the key start quote.
    let cases = [
        {
            name: "string with zero-length key",
            data: `{"":"foo"}`,
            key: "",
            value: `"foo"`,
            valid: true
        },
        {
            name: "array",
            data: `{"foo":["bar","baz"]}`,
            key: "foo",
            value: `["bar","baz"]`,
            valid: true,
        },
        {
            name: "Key wildcard, bool",
            data: `{"foo":true}`,
            key: "\x00o",
            key_len: 3,
            value: `true`,
            valid: true,
        },
        {
            name: "Key wildcard, bool, bad key",
            data: `{"foo":true}`,
            key: "\x00x",
            key_len: 3,
            value: `true`,
            valid: false,
        },
        {
            name: "bad value",
            data: `{"":"foo"}`,
            key: "",
            value: `"fox"`,
            valid: false
        },
        {
            // This test is not about required functionality, but to detect when this behavior changes
            name: "key overflow",
            data: `{"":"foo"}`,
            key: `":"foo"}`,
            key_len: 0,
            value: `"foo"`,
            valid: true
        },
        {
            // This test is not about required functionality, but to detect when this behavior changes
            name: "value overflow",
            data: `{"":"foo"}`,
            key: "",
            value: `"foo"}`,
            valid: true
        },
        {
            name: "partial 1",
            data: `,"foo":["bar","baz"] `,
            key: "foo",
            value: `["bar","baz"]`,
            valid: true,
        },
        {
            name: "partial 2",
            data: `\n"foo":["bar","baz"],\n`,
            key: "foo",
            value: `["bar","baz"]`,
            valid: true,
        },
        {
            name: "array partial",
            data: `{"foo":["bar","baz"]}`,
            key: "foo",
            value: `["bar",`,
            valid: true,
        },
        {
            name: "value as key",
            data: ` "bar","baz":true}`,
            key: "bar",
            value: ``,
            valid: false
        },
        {
            name: "detects partial key",
            data: `\"foo":"bar"}`,
            key: "foo",
            value: ``,
            valid: false
        },
        // This one is really really hard to detect. It is however usually apparent by a key length missmatch or the key ending
        // with a partial escape sequence. It is not possible to cause this without such a partial escape, but checking
        // for these escapes in the circuit is difficult, unless we set a maximum limit of consequtive '\' characters at the end of the key.
        // I've decided to not check this in the circuit and leave this up to the verifier (who should check key and key_len anyways).
        // {
        //     name: "escaped",
        //     data: `:"foo\\":true"}`,
        //     key: "foo",
        //     key_len: 4,
        //     value: ``,
        //     valid: false
        // },
        // This is basically impossible to detect, same with similar keys that are a valid sequence in
        // json that can be followed by a quote and arbitrary data.
        // {
        //     name: "gap as key",
        //     data: `y":":true"}`,
        //     key: ":",
        //     value: `true`,
        //     valid: false,
        // }
    ];

    for (let i = 0; i < cases.length; i++) {
        it(cases[i].name, async () => {
            var valid = true;
            try {
                const witness = await circuit.calculateWitness({
                    data: str2paddedBytes(cases[i].data, 128),
                    key: str2paddedBytes(cases[i].key, 32),
                    key_length: cases[i].key_len ?? cases[i].key.length,
                    value: str2paddedBytes(cases[i].value, 64),
                    sep: 58, // ':'
                });

                await circuit.checkConstraints(witness);
            } catch (e) {
                valid = false;
                if (cases[i].valid) {
                    throw e;
                }
            }

            if (cases[i].valid != valid) {
                throw "Expected constraints to not be fulfilled but they where"
            }
        });
    }
});

describe("JsonGetSDValue", () => {
    jest.setTimeout(5 * 60 * 1000) // 5 minutes

    let circuit: any;

    beforeAll(async () => {
        // Compile the circuit
        circuit = await wasm_tester(path.join(__dirname, "./test-circuits/jsonGetSDEntry.circom"), {
            recompile: true,
            include: path.join(__dirname, "../")
        })
    });

    let cases = [
        {
            name: "minimal single",
            data: `{"_sd":["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"`,
            distance: 0,
            value: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
            valid: true
        },
        {
            name: "minimal first",
            data: `{"_sd":["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`,
            distance: 0,
            value: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
            valid: true
        },
        {
            name: "minimal second",
            data: `{"_sd":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"`,
            distance: 46,
            value: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
            valid: true
        },
        {
            name: "pretty second",
            data: ` "_sd": [
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"`,
            distance: 1 + 9 + 46 + 9,
            value: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
            valid: true
        }
    ];

    for (let i = 0; i < cases.length; i++) {
        it(cases[i].name, async () => {
            var valid = true;
            var witness;
            try {
                witness = await circuit.calculateWitness({
                    data: str2paddedBytes(cases[i].data, 256),
                    distance2quote: cases[i].distance,
                });

                await circuit.checkConstraints(witness);
            } catch (e) {
                valid = false;
                if (cases[i].valid) {
                    throw e;
                }
            }


            if (cases[i].valid != valid) {
                throw "Expected constraints to not be fulfilled but they where"
            }

            if (cases[i].valid) {
                await circuit.assertOut(witness, {
                    value: str2paddedBytes(cases[i].value, 43),
                });
            }
        });
    }
});

function str2paddedBytes(data: string, len: number): number[] {
    const bytes = [...data].map(c => c.charCodeAt(0));

    if (bytes.length > len) {
        throw new Error(`String too long: ${bytes.length} > ${len}`);
    }

    return [...bytes, ...Array(len - bytes.length).fill(0)];
}
