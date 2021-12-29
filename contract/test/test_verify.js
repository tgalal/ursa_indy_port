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

function load_ne_proof() {
    return load_test_file("ne_proof");
}

function bnToBnHex(bn) {
    const bnStr = bn.toString(16);

    let enc_zeros = "";
    while((enc_zeros + bnStr).length % 64 != 0)
        enc_zeros += "0";
    
    const concat = "0x" + enc_zeros + bnStr;

    return concat;
}

function decStrToBnHex(str) {
    const bn = new BN(str, 10);
    return bnToBnHex(bn);
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

    it("returns 2^596", () => {
        const bnStr = "259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742929677132122730441323862712594345230336";
        
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

contract("Verify", (accounts) => {
    it("test_calc_teq", () => {
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

        let contract;
        return Verify.deployed()
            .then((_contract) => {
                contract = _contract;
                return contract.calc_teq.call(params, {gas: 299706180000});
            })
            .then((_result) => {
                const expected = new BN("91264240506826174927348047353965425159860757123338479073424113940259806551851229292237119667270337226044891882031507391247335164506822323444174803404823415595209988313925779411601427163169867402731683535732199690625942446654645156277416114003097696459602759772355589838338098112196343083991333232435443953495090160789157756256594127180544038043918022344493848651792154647005487993074823035954414813424278780163108302094976055852493721853967615097172351343103854345595377663442839788671277249341676912758940126819293663537960202673372394563353933943790374230983129060596346889726181201177754774157687114812348019929279", 10);
                const result = hexStrToDecStr(_result[0]);

                assert.equal(result, expected.toString());
            })
            .then(async () => { // sendTransaction
                console.log("Gas: " + (await contract.calc_teq.sendTransaction(params, {gas: 299706180})).receipt.gasUsed);
            })
    });

    it("test_calc_tne", () => {
        const proof = load_ne_proof();
        const credentials_proof = load_credential_primary_public_key();

        const u_keys = Object.keys(proof.u);
        const u_values = u_keys.map(e => decStrToBnHex(proof.u[e]));

        const r_keys = Object.keys(proof.r);
        const r_values = r_keys.map(e => decStrToBnHex(proof.r[e]));

        const t_keys = Object.keys(proof.t);
        const t_values = t_keys.map(e => decStrToBnHex(proof.t[e]));

        const is_less = proof["predicate"]["p_type"].toUpperCase() == "LE" || proof["predicate"]["p_type"].toUpperCase() == "LT";

        const params = {
            "p_pub_key_n": decStrToBnHex(credentials_proof["n"]),
            "p_pub_key_z": decStrToBnHex(credentials_proof["z"]),
            "p_pub_key_s": decStrToBnHex(credentials_proof["s"]),

            u_keys,
            u_values,

            r_keys,
            r_values,

            t_keys,
            t_values,

            is_less,

            "mj": decStrToBnHex(proof["mj"]),
            "alpha": decStrToBnHex(proof["alpha"])
        }

        let contract;
        return Verify.deployed()
            .then((_contract) => {
                contract = _contract;
                return contract.calc_tne.call(params, {gas: 299706180000});
            })
            .then((_result) => {
                const expected1 = new BN("65515179709108026467913442253499099801966907020745255347110398650355916665803837070743742856256239926182580344828747056374854996387593743341119067779984445971959628821374954624125259986776588712694484260532223243155004707730091232554480477132219992945402707566277358152501360632014253935013985662381916247720671148707249946908885935798495651223006117551824336990348194142359095214983750938766847922335263906099668502110108213509816408727203285417799732710557464731810621993308635556837149106069127879412025831831902348616785489451865822186524800436027192696216152105090506015757266556255232306144655608567343136505670", 10);
                const expected4 = new BN("37533780917779531511237145959836444300689607963031476900866684621488489918126566549521889953514727910575781249476835854546757846221784411088089185036186792246785963648143366397502159012152353145753888331365853963358155135442054751416620007628556393795100498260908294371022811442070620351098758127098244798879430407810333937749563329381152076445529402863878168823425796701343716083092433240425563155523357082891438811091111226019426720893504830292043278152141736791123288773813527455078223655469497666616699048262253832499575715918268161607620654341861117070040350723055043721492475393447378422268465089327305214127497", 10);
                const expected5 = new BN("85792352895820240333890789102145726421844499161302737480886489756497939690747882476232993619450034358080431321661007128196198281806423085966407473046006187053994245452998741843631201950275110777364312249003319362038697793775377082322949653888826775245421712887332420051752162962176051068381742850661487019199688955385460549344136833325388021671633290649550405155653891490163080779548518087060830955821092481708474638805362493661566057142675967527663183993708768033669078126632504366308385415802955961151772167870231474144073772802283182375145256219426454149503998537986414519426715148839164974816475472185621648644891", 10);


                const result1 = hexStrToDecStr(_result["_val"][1]);
                const result4 = hexStrToDecStr(_result["_val"][4]);
                const result5 = hexStrToDecStr(_result["_val"][5]);

                assert.equal(result1, expected1.toString());
                assert.equal(result4, expected4.toString());
                assert.equal(result5, expected5.toString());
            })
            .then(async () => { // sendTransaction
                console.log("Gas: " + (await contract.calc_tne.sendTransaction(params, {gas: 299706180})).receipt.gasUsed);
            })
    });

    it("verify_equality", () => {
        const proof = load_primary_eq_proof();
        const credentials_proof = load_credential_primary_public_key();

        const revealed_attrs = Object.keys(proof["revealed_attrs"]);
        const revealed_attrs_values = revealed_attrs.map(e => decStrToBnHex(proof["revealed_attrs"][e]));
        const unrevealed_attrs = ["master_secret", "height", "age", "sex"];

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

        const two_596 = decStrToBnHex("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742929677132122730441323862712594345230336");

        const aggregated_proof = load_test_file("aggregated_proof");

        const z = decStrToBnHex(credentials_proof["z"]);
        const z_inverted = bnToBnHex(new BN(credentials_proof["z"], 10).invm(new BN(credentials_proof["n"], 10)));

        let contract;
        return Verify.deployed()
            .then((_contract) => {
                contract = _contract;
                return contract.verify_equality.call(
                    params, 
                    z,
                    z_inverted,
                    two_596,
                    revealed_attrs,
                    revealed_attrs_values,
                    decStrToBnHex(aggregated_proof.c_hash),
                    { gas: 299706180000 });
            })
            .then((_result) => {
                const expected = new BN("10403187904873314760355557832761590691431383521745031865309573910963034393207684410473727200515283477478376473602591257259106279678624852029355519315648291936226793749327383847453659785035143404901389180684693937348170201350989434402765939255768789625180291625978184555673228742169810564578048461551461925810052930346018787363753466820600660809185539201223715614073753236155593704206176748170586820334068878049220243421829954440440126364488974499959662371883050129101801650402485085948889890560553367693634003096560104152231733949195252484402507347769428679283112853202405399796966635008669186194259851326316679551259", 10);
                const result = hexStrToDecStr(_result[0]);

                assert.equal(result, expected.toString());
            })
            .then(async () => { // sendTransaction
                console.log("Gas: " + (await contract.verify_equality.sendTransaction(
                    params, 
                    z,
                    z_inverted,
                    two_596,
                    revealed_attrs,
                    revealed_attrs_values,
                    decStrToBnHex(aggregated_proof.c_hash),
                    { gas: 299706180 })).receipt.gasUsed);
            })
    });

    it("verify_ne_predicate", () => {
        const proof = load_ne_proof();
        const credentials_proof = load_credential_primary_public_key();

        const u_keys = Object.keys(proof.u);
        const u_values = u_keys.map(e => decStrToBnHex(proof.u[e]));

        const r_keys = Object.keys(proof.r);
        const r_values = r_keys.map(e => decStrToBnHex(proof.r[e]));

        const t_keys = Object.keys(proof.t);
        const t_values = t_keys.map(e => decStrToBnHex(proof.t[e]));

        const is_less = proof["predicate"]["p_type"].toUpperCase() == "LE" || proof["predicate"]["p_type"].toUpperCase() == "LT";

        const tne_params = {
            "p_pub_key_n": decStrToBnHex(credentials_proof["n"]),
            "p_pub_key_z": decStrToBnHex(credentials_proof["z"]),
            "p_pub_key_s": decStrToBnHex(credentials_proof["s"]),

            u_keys,
            u_values,

            r_keys,
            r_values,

            t_keys,
            t_values,

            is_less,

            "mj": decStrToBnHex(proof["mj"]),
            "alpha": decStrToBnHex(proof["alpha"])
        };

        const aggregated_proof = load_test_file("aggregated_proof");
        const c_hash =  new BN(aggregated_proof.c_hash, 10);

        const cur_t_inverse_keys = t_keys;
        const cur_t_inverse_values = t_keys
                .map(t => proof.t[t])
                .map(val => new BN(val, 10))
                .map(bn => bn.invm(new BN(credentials_proof["n"], 10)))
                .map(bn => bnToBnHex(bn));

        const proof_t_delta_inverse = new BN(proof["t"]["DELTA"], 10).invm(new BN(credentials_proof["n"], 10));

        const predicate_get_delta_prime = () => {
            if(proof["predicate"]["p_type"] == "GT") {
                return new BN(proof["predicate"]["value"], 10).add(1);
            } else if(proof["predicate"]["p_type"] == "LT") {
                return new BN(proof["predicate"]["value"], 10).sub(1);
            } else {
                return new BN(proof["predicate"]["value"], 10);
            }
        };

        const tau_delta_intermediate_inverse = () => {
            const delta = new BN(proof["t"]["DELTA"], 10);
            const delta_prime = is_less ? proof_t_delta_inverse : delta;

            const p_pub_key_n = new BN(credentials_proof["n"], 10);
            
            const red = BN.red(p_pub_key_n);
            
            let tau_delta_intermediate = new BN(credentials_proof["z"], 10).toRed(red);

            tau_delta_intermediate = tau_delta_intermediate.redPow(predicate_get_delta_prime());
            tau_delta_intermediate = tau_delta_intermediate.redMul(delta_prime.toRed(red));
            tau_delta_intermediate = tau_delta_intermediate.redPow(c_hash);
            return tau_delta_intermediate.fromRed().invm(p_pub_key_n);
        };

        const tau_5_intermediate_inverse = () => {
            const delta = new BN(proof["t"]["DELTA"], 10);
            const p_pub_key_n = new BN(credentials_proof["n"], 10);
            const red = BN.red(p_pub_key_n);

            let tau_5_intermediate_inverse = delta.toRed(red);
            tau_5_intermediate_inverse = tau_5_intermediate_inverse.redPow(c_hash);
            return tau_5_intermediate_inverse.fromRed().invm(p_pub_key_n);
        };

        const verify_ne_params = {
            "c_hash": decStrToBnHex(c_hash),
            cur_t_inverse_keys,
            cur_t_inverse_values,
            "proof_t_delta_inverse": bnToBnHex(proof_t_delta_inverse),
            "predicate_delta_prime_value": bnToBnHex(predicate_get_delta_prime()),
            "tau_delta_intermediate_inverse": bnToBnHex(tau_delta_intermediate_inverse()),
            "tau_5_intermediate_inverse": bnToBnHex(tau_5_intermediate_inverse())
        };

        let contract;
        return Verify.deployed()
            .then((_contract) => {
                contract = _contract;
                return contract.verify_ne_predicate(
                    tne_params, 
                    verify_ne_params,
                    { from: accounts[0], gas: 299706180 });
            })
            .then((_result) => {
                const expected0 = new BN("84541983257221862363846490076513159323178083291858042421207690118109227097470776291565848472337957726359091501353000902540328950379498905188603938865076724317214320854549915309320726359461624961961733838169355523220988096175066605668081002682252759916826945673002001231825064670095844788135102734720995698848664953286323041296412437988472201525915887801570701034703233026067381470410312497830932737563239377541909966580208973379062395023317756117032804297030709565889020933723878640112775930635795994269000136540330014884309781415188247835339418932462384016593481929101948092657508460688911105398322543841514412679282", 10);
                const expected4 = new BN("84541983257221862363846490076513159323178083291858042421207690118109227097470776291565848472337957726359091501353000902540328950379498905188603938865076724317214320854549915309320726359461624961961733838169355523220988096175066605668081002682252759916826945673002001231825064670095844788135102734720995698848664953286323041296412437988472201525915887801570701034703233026067381470410312497830932737563239377541909966580208973379062395023317756117032804297030709565889020933723878640112775930635795994269000136540330014884309781415188247835339418932462384016593481929101948092657508460688911105398322543841514412679282", 10);
                const expected5 = new BN("71576740094469616050175125038612941221466947853166771156257978699698137573095744200811891005812207466193292025189595165749324584760557051762243613675513037542326352529889732378990457572908903168034378406865820691354892874894693473276515751045246421111011260438431516865750528792129415255282372242857723274819466930397323134722222564785435619193280367926994591910298328813248782022939309948184632977090553101391015001992173901794883378542109254048900040301640312902056379924070500971247615062778344704821985243443504796944719578450705940345940533745092900800249667587825786217899894277583562804465078452786585349967293", 10);


                const result0 = hexStrToDecStr(_result["_val"][0]);
                const result4 = hexStrToDecStr(_result["_val"][4]);
                const result5 = hexStrToDecStr(_result["_val"][5]);

                assert.equal(result0, expected0.toString());
                assert.equal(result4, expected4.toString());
                assert.equal(result5, expected5.toString());                
            })
            .then(async () => {
                console.log("Gas: " + (await contract.verify_ne_predicate.sendTransaction(
                    tne_params, 
                    verify_ne_params,
                    { from: accounts[0], gas: 299706180 })).receipt.gasUsed);
            })
    })
});