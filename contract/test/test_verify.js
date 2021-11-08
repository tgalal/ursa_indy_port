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

function addBNParam(name, strInt, obj) {
    let newObj = obj !== undefined ? {...obj} : new Object();
    
    const bn = new BN(strInt);
    const bnStr = bn.toString(16);

    newObj[name] = bnStr.length % 2 === 0 ? "0x" + bnStr : "0x0" + bnStr;
    newObj[name + "_bits"] = bn.bitLength();

    return newObj;
}

contract("BigNumber", () => {
    it("returns a small number (13)", () => {
        return BigNumberTest.deployed()
            .then((instance) => {
                const bn = new BN("13");

                // https://github.com/indutny/bn.js/#utilities
                return instance.returnBigNumber.call(
                    "0x" + bn.toString(16),
                    bn.bitLength() 
                );
            })
            .then((result) => {
                assert.equal(result[0], "0x0d");
                assert.equal(result[1], false);
                assert.equal(result[2].toNumber(), 4);
            });
    });

    it("returns a big number", () => {
        const bnStr = "91264240506826174927348047353965425159860757123338479073424113940259806551851229292237119667270337226044891882031507391247335164506822323444174803404823415595209988313925779411601427163169867402731683535732199690625942446654645156277416114003097696459602759772355589838338098112196343083991333232435443953495090160789157756256594127180544038043918022344493848651792154647005487993074823035954414813424278780163108302094976055852493721853967615097172351343103854345595377663442839788671277249341676912758940126819293663537960202673372394563353933943790374230983129060596346889726181201177754774157687114812348019929279";
        const bnStrHex = "2d2f3b91a9bbb8c5e086c6934c500b45990ee23bab1efbe28e27c3fc05d49c37abf73c1b25c7739ea847e80e0e1dd7a83a04cda970a11f5ad597fb67e16e5eca669fb87ce40dc833943fa8ddc7f983f717fc8cc556275881b9e55b548bf514d3cb6ac9a83bd2c6c84c70e175bd275d3e360496ce6e01e68a2c0384053259a346f5e5c6acc2481431734919ec0c673a31da69c36877510a4c454ef90923d20bf6ca3eb8af0cc17a0a162e1e34ba3a82cda29b34f025e642a474fc69034fef8dd798d0880c41fa2929fe1dce94e0be9fcf6d72862f602b7977efe39ffcc52e18311e244efe8ab4a1bb2f78d1c6189eec4d942bae5710220cdae4297d0a8f70a70bf";
        const bn = new BN(bnStr);
        
        return BigNumberTest.deployed()
            .then((instance) => {        
                const bnStr = bn.toString(16);

                return instance.returnBigNumber.call(
                    bnStr.length % 2 === 0 ? "0x" + bnStr : "0x0" + bnStr,
                    bn.bitLength() 
                );
            })
            .then((result) => {
                assert.equal(result[0], "0x0" + bnStrHex);
                assert.equal(result[1], false);
                assert.equal(result[2].toNumber(), bn.bitLength());
            });
    });
})

contract("Verify", () => {
    it("test_calc_teq", () => {
        const expected = new BN("91264240506826174927348047353965425159860757123338479073424113940259806551851229292237119667270337226044891882031507391247335164506822323444174803404823415595209988313925779411601427163169867402731683535732199690625942446654645156277416114003097696459602759772355589838338098112196343083991333232435443953495090160789157756256594127180544038043918022344493848651792154647005487993074823035954414813424278780163108302094976055852493721853967615097172351343103854345595377663442839788671277249341676912758940126819293663537960202673372394563353933943790374230983129060596346889726181201177754774157687114812348019929279");

        const proof = load_primary_eq_proof();
        const credentials_proof = load_credential_primary_public_key();

        const params = {
            ...addBNParam("p_pub_key_n", credentials_proof["n"]),
            ...addBNParam("a_prime", proof["a_prime"]),
            ...addBNParam("e", proof["e"])
        };

        console.log(params);

        return Verify.deployed()
            .then((contract) => {
                return contract.calc_teq.call(params);
            })
            .then((result) => {
                console.log(result);
            })


        //console.log(proof);

        // const p_pub_key_n = new BN();

        // bytes memory p_pub_key_n,
        // uint256 p_pub_key_n_bits,

        // bytes memory p_pub_key_s,
        // bytes memory p_pub_key_rctxt,

        // bytes[] memory r_unrevealed_attrs_values,
        // string[] memory r_unrevealed_attrs_keys,

        // bytes[] memory m_revealed_attrs_values,
        // string[] memory m_revealed_attrs_keys,

        // bytes memory a_prime,
        // uint256 a_prime_bits,

        // bytes memory e,
        // uint256 e_bits,

        // bytes memory v,
        // uint256 v_bits,

        // bytes memory mtilde,
        // uint256 mtilde_bits

        // const res = calc_teq(
        //     p_pub_key=load_credential_primary_public_key(),
        //     a_prime=proof["a_prime"],
        //     e=proof["e"],
        //     v=proof["v"],
        //     m_tilde=proof["m"],
        //     m2tilde=proof["m2"],
        //     unrevealed_attrs=load_unrevealed_attrs()
        // );

        // assert.equal(res, expected)
    })
});