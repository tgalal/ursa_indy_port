pragma solidity >=0.4.20 <0.6;
pragma experimental ABIEncoderV2;

import "./BigNumber.sol";

contract Verify {
	using BigNumber for *;

	struct Calc_teq_param {
		bytes p_pub_key_n;
		bytes p_pub_key_s;
		bytes p_pub_key_rctxt;

		string[] unrevealed_attrs;

		string[] p_pub_key_r_keys;
		bytes[] p_pub_key_r_values;

		string[] m_tilde_keys;
		bytes[] m_tilde_values;

		bytes a_prime;
		bytes e;
		bytes v;
		bytes m2tilde;
	}


	function getParamValue(
			bytes32 _key, 
			string[] memory _keys, 
			bytes[] memory _values
	) view public returns (BigNumber.instance memory) {
		require(_keys.length == _values.length);

		for(uint256 i = 0; i < _keys.length; i++) {
			if(_key == keccak256(bytes(_keys[i]))) {
				return BigNumber._new(_values[i], false, false);
			}
		}

		revert();
	}

	function calc_teq_result_0(
			bytes memory _a_prime, 
			bytes memory _e, 
			BigNumber.instance memory _p_pub_key_n
	) view public returns (BigNumber.instance memory _result_0) {
		BigNumber.instance memory a_prime = BigNumber._new(_a_prime, false, false);
		BigNumber.instance memory e = BigNumber._new(_e, false, false);

		_result_0 = a_prime.prepare_modexp(e, _p_pub_key_n);
	}

	function calc_teq_result_k(
			BigNumber.instance memory _result_0, 
			string[] memory _unrevealed_attrs, 
			string[] memory _p_pub_key_r_keys, 
			bytes[] memory _p_pub_key_r_values, 
			string[] memory _m_tilde_keys, 
			bytes[] memory _m_tilde_values, 
			BigNumber.instance memory _p_pub_key_n
	) view public returns (BigNumber.instance memory _result_k) {

		BigNumber.instance memory modexp;

		_result_k = _result_0;

		for(uint256 i = 0; i < _unrevealed_attrs.length; i++) {
			bytes32 k = keccak256(bytes(_unrevealed_attrs[i]));

			BigNumber.instance memory cur_r = getParamValue(k, _p_pub_key_r_keys, _p_pub_key_r_values);
			BigNumber.instance memory cur_m = getParamValue(k, _m_tilde_keys, _m_tilde_values);

			modexp = cur_r.prepare_modexp(cur_m, _p_pub_key_n);

			_result_k = modexp.modmul(_result_k, _p_pub_key_n);
		}
	}

	function calc_teq_result_1(
			BigNumber.instance memory _result_k, 
			bytes memory _p_pub_key_s, 
			bytes memory _v,
			BigNumber.instance memory _p_pub_key_n
	) view public returns (BigNumber.instance memory _result_1) {
		BigNumber.instance memory p_pub_key_s = BigNumber._new(_p_pub_key_s, false, false);
		BigNumber.instance memory v = BigNumber._new(_v, false, false);

		_result_1 = p_pub_key_s.prepare_modexp(v, _p_pub_key_n);
		_result_1 = _result_1.modmul(_result_k, _p_pub_key_n);
	}

	function calc_teq_result_2(
			BigNumber.instance memory _result_1, 
			bytes memory _p_pub_key_rctxt, 
			bytes memory _m2tilde,
			BigNumber.instance memory _p_pub_key_n
	) view public returns (BigNumber.instance memory _result_2) {
		BigNumber.instance memory p_pub_key_rctxt = BigNumber._new(_p_pub_key_rctxt, false, false);
		BigNumber.instance memory m2tilde = BigNumber._new(_m2tilde, false, false);

		_result_2 = p_pub_key_rctxt.prepare_modexp(m2tilde, _p_pub_key_n);
		_result_2 = _result_2.modmul(_result_1, _p_pub_key_n);
	}

	function calc_teq(
			Calc_teq_param memory _params
	) view public returns (bytes memory, bool, uint) {
		BigNumber.instance memory p_pub_key_n = BigNumber._new(_params.p_pub_key_n, false, false);
		
		BigNumber.instance memory result = calc_teq_result_0(_params.a_prime, _params.e, p_pub_key_n);

		result = calc_teq_result_k(
			result,
			_params.unrevealed_attrs,
			_params.p_pub_key_r_keys,
			_params.p_pub_key_r_values,
			_params.m_tilde_keys,
			_params.m_tilde_values,
			p_pub_key_n
		);

		result = calc_teq_result_1(
			result,
			_params.p_pub_key_s,
			_params.v,
			p_pub_key_n
		);
		
		result = calc_teq_result_2(
			result,
			_params.p_pub_key_rctxt,
			_params.m2tilde,
			p_pub_key_n
		);

		return (result.val, result.neg, result.bitlen);
	}
}