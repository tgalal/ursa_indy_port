pragma solidity >=0.4.20 <0.6;
pragma experimental ABIEncoderV2;

import "./BigNumber.sol";

contract Verify {
	using BigNumber for *;

	struct Calc_teq_param {
		bytes p_pub_key_n;
		uint256 p_pub_key_n_bits;

		string[] unrevealed_attrs;

		string[] r_keys;
		bytes[] r_values;
		uint256[] r_sizes;

		string[] m_keys;
		bytes[] m_values;
		uint256[] m_sizes;

		bytes a_prime;
		uint256 a_prime_bits;

		bytes e;
		uint256 e_bits;

		/*bytes v;
		uint256 v_bits;

		bytes mtilde;
		uint256 mtilde_bits;*/
	}

	BigNumber.instance one = BigNumber.instance(hex"0000000000000000000000000000000000000000000000000000000000000001",false,1);
	BigNumber.instance two = BigNumber.instance(hex"0000000000000000000000000000000000000000000000000000000000000002",false,2);

	function getParamValue(bytes32 _key, string[] memory _keys, bytes[] memory _values, uint256[] memory _sizes) public returns (BigNumber.instance memory) {
		require(_keys.length == _values.length);

		for(uint256 i = 0; i < _keys.length; i++) {
			if(_key == keccak256(bytes(_keys[i]))) {
				return BigNumber.instance(_values[i], false, _sizes[i]);
			}
		}

		revert();
	}

	function calc_teq(Calc_teq_param memory _params
		
	) public returns (bytes memory, bool, uint) {
		BigNumber.instance memory p_pub_key_n = BigNumber.instance(_params.p_pub_key_n, false, _params.p_pub_key_n_bits);
		BigNumber.instance memory a_prime = BigNumber.instance(_params.a_prime, false, _params.a_prime_bits);
		BigNumber.instance memory e = BigNumber.instance(_params.e, false, _params.e_bits);

		BigNumber.instance memory result = a_prime.prepare_modexp(e, p_pub_key_n);


		for(uint256 i = 0; i < _params.unrevealed_attrs.length; i++) {
			bytes32 k = keccak256(bytes(_params.unrevealed_attrs[i]));

			BigNumber.instance memory cur_r = getParamValue(k, _params.r_keys, _params.r_values, _params.r_sizes);
			BigNumber.instance memory cur_m = getParamValue(k, _params.m_keys, _params.m_values, _params.m_sizes);

			BigNumber.instance memory modexp = cur_r.prepare_modexp(cur_m, p_pub_key_n);
			result = modexp.modmul(result, p_pub_key_n);
		}

		return (result.val, result.neg, result.bitlen);
	}
}