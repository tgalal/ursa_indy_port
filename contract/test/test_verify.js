const fs = require("fs");
const Web3 = require("web3");
const BN = Web3.utils.BN; 

const BigNumberTest = artifacts.require("BigNumberTest");
const Verify = artifacts.require("Verify");

function load_test_file(name) {
    const fileJson = fs.readFileSync("../data/tests/" + name + ".json", "utf8");
    const obj = JSON.parse(fileJson);
    return obj;
}

function load_credential_primary_public_key() {
    return load_test_file("credential_primary_public_key");
}

function load_primary_eq_proof() {
    return load_test_file("primary_eq_proof");
}

function decStrToBnHex(str) {
    const bn = new BN(str, 10);
    const bnStr = bn.toString(16);

    let enc_zeros = "";
    while((enc_zeros + bnStr).length % 64 != 0)
        enc_zeros += "0";
    
    const concat = "0x" + enc_zeros + bnStr;

    return concat;
}

function hexStrToDecStr(str) {
    const bnStr = str.replace(/^0x0*/g, "");
    return new BN(bnStr, 16).toString();
}

contract("BigNumber", () => {
    it("converts 0x0.....0d to 13", () => {
        assert.equal(hexStrToDecStr("0x000000000000000000000000000000000000000000000000000000000000000d"), "13");
    });

    it("returns a small number (13)", () => {
        return BigNumberTest.deployed()
            .then((instance) => {
                return instance.returnBigNumber.call(
                    "0x000000000000000000000000000000000000000000000000000000000000000d"
                );
            })
            .then((result) => {
                assert.equal(result[0], "0x000000000000000000000000000000000000000000000000000000000000000d");
                assert.equal(hexStrToDecStr(result[0]), "13");
                assert.equal(result[1], false);
                assert.equal(result[2].toNumber(), 4);
            })
    });

    it("returns a small number (14)", () => {
        return BigNumberTest.deployed()
            .then((instance) => {
                // https://github.com/indutny/bn.js/#utilities
                return instance.returnBigNumber.call(
                    decStrToBnHex("14")
                );
            })
            .then((result) => {
                assert.equal(result[0], "0x000000000000000000000000000000000000000000000000000000000000000e");
                assert.equal(hexStrToDecStr(result[0]), "14");
                assert.equal(result[1], false);
                assert.equal(result[2].toNumber(), 4);
            });
    });

    it("returns a big number", () => {
        const bnStr = "91264240506826174927348047353965425159860757123338479073424113940259806551851229292237119667270337226044891882031507391247335164506822323444174803404823415595209988313925779411601427163169867402731683535732199690625942446654645156277416114003097696459602759772355589838338098112196343083991333232435443953495090160789157756256594127180544038043918022344493848651792154647005487993074823035954414813424278780163108302094976055852493721853967615097172351343103854345595377663442839788671277249341676912758940126819293663537960202673372394563353933943790374230983129060596346889726181201177754774157687114812348019929279";
        
        return BigNumberTest.deployed()
            .then((instance) => {        
                return instance.returnBigNumber.call(
                    decStrToBnHex(bnStr)
                );
            })
            .then((result) => {
                assert.equal(hexStrToDecStr(result[0]), bnStr);
                assert.equal(result[1], false);
            });
    });
})

contract("Verify", () => {
    it("test_calc_teq", () => {
        const expected = new BN("91264240506826174927348047353965425159860757123338479073424113940259806551851229292237119667270337226044891882031507391247335164506822323444174803404823415595209988313925779411601427163169867402731683535732199690625942446654645156277416114003097696459602759772355589838338098112196343083991333232435443953495090160789157756256594127180544038043918022344493848651792154647005487993074823035954414813424278780163108302094976055852493721853967615097172351343103854345595377663442839788671277249341676912758940126819293663537960202673372394563353933943790374230983129060596346889726181201177754774157687114812348019929279", 10);

        const proof = load_primary_eq_proof();
        const credentials_proof = load_credential_primary_public_key();

        const unrevealed_attrs = ["height", "age", "sex"];

        const r_keys = Object.keys(credentials_proof.r);
        const r_values = r_keys.map(e => decStrToBnHex(credentials_proof.r[e]));

        const m_keys = Object.keys(proof.m);
        const m_values = m_keys.map(e => decStrToBnHex(proof.m[e]));

        const params = {
            "p_pub_key_n": decStrToBnHex(credentials_proof["n"]),
            "p_pub_key_s": decStrToBnHex(credentials_proof["s"]),
            "p_pub_key_rctxt": decStrToBnHex(credentials_proof["rctxt"]),
            unrevealed_attrs,
            p_pub_key_r_keys: r_keys,
            p_pub_key_r_values: r_values,
            m_tilde_keys: m_keys,
            m_tilde_values: m_values,
            
            "a_prime": decStrToBnHex(proof["a_prime"]),
            "e": decStrToBnHex(proof["e"]),


            "v": decStrToBnHex(proof["v"]),
            "m2tilde": decStrToBnHex(proof["m2"])
        };

        //console.log(params);

        let contract;
        return Verify.deployed()
            .then((_contract) => {
                contract = _contract;
                return contract.calc_teq.call(params, {gas: 299706180000});
            })
            .then((_result) => {
                const result = hexStrToDecStr(_result[0]);

                assert.equal(result, expected.toString());
            })
    })
});