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

	struct Calc_tne_param {
		bytes p_pub_key_n;
		bytes p_pub_key_z;
		bytes p_pub_key_s;

		string[] u_keys;
		bytes[] u_values;

		string[] r_keys;
		bytes[] r_values;

		string[] t_keys;
		bytes[] t_values;

		bool is_less;

		bytes mj;
		bytes alpha;
	}

	struct Verify_ne_predicate_param {
		bytes c_hash;
 		string[] cur_t_inverse_keys;
 		bytes[] cur_t_inverse_values;
 		bytes proof_t_delta_inverse;
 		bytes predicate_delta_prime_value;
 		bytes tau_delta_intermediate_inverse;
 		bytes tau_5_intermediate_inverse;
 	}

	BigNumber.instance public minusOne = BigNumber._new(hex"0000000000000000000000000000000000000000000000000000000000000001", true, false);

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

	function getIntStrHash(uint8 _i) pure public returns (bytes32 _hash) {
		// int to string (48 is ascii "0")
		bytes memory i_str = new bytes(1);
		i_str[0] = bytes1(uint8(48 + _i));

		_hash = keccak256(i_str);
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

	function calc_tne_result_tau_i(
		uint8 _i,
		Calc_tne_param memory _params,
		BigNumber.instance memory _p_pub_key_n,
		BigNumber.instance memory _p_pub_key_z,
		BigNumber.instance memory _p_pub_key_s
	) view public returns (BigNumber.instance memory _result_tau_i) {
		bytes32 k = getIntStrHash(_i);

		BigNumber.instance memory cur_u = getParamValue(k, _params.u_keys, _params.u_values);
		BigNumber.instance memory cur_r = getParamValue(k, _params.r_keys, _params.r_values);

		BigNumber.instance memory pow_z_u_mod_n = _p_pub_key_z.prepare_modexp(cur_u, _p_pub_key_n);
		BigNumber.instance memory pow_s_r_mod_n = _p_pub_key_s.prepare_modexp(cur_r, _p_pub_key_n);

		_result_tau_i = pow_z_u_mod_n.modmul(pow_s_r_mod_n, _p_pub_key_n);
	}

	function calc_tne_result_tau_4(
		BigNumber.instance memory _delta,
		bytes memory _mj,
		BigNumber.instance memory _p_pub_key_n,
		BigNumber.instance memory _p_pub_key_z,
		BigNumber.instance memory _p_pub_key_s
	) view public returns (BigNumber.instance memory _result_tau_4) {
		BigNumber.instance memory mj = BigNumber._new(_mj, false, false);

		BigNumber.instance memory pow_z_mj_mod_n = _p_pub_key_z.prepare_modexp(mj, _p_pub_key_n);
		BigNumber.instance memory pow_s_delta_mod_n = _p_pub_key_s.prepare_modexp(_delta, _p_pub_key_n);

		_result_tau_4 = pow_z_mj_mod_n.modmul(pow_s_delta_mod_n, _p_pub_key_n);
	}

	function calc_tne_result_q_i(
		uint8 _i,
		BigNumber.instance memory _q,
		Calc_tne_param memory _params,
		BigNumber.instance memory _p_pub_key_n
	) view public returns (BigNumber.instance memory _result_q_i) {
		bytes32 k = getIntStrHash(_i);

		BigNumber.instance memory cur_t = getParamValue(k, _params.t_keys, _params.t_values);
		BigNumber.instance memory cur_u = getParamValue(k, _params.u_keys, _params.u_values);

		BigNumber.instance memory pow_t_u_mod_n = cur_t.prepare_modexp(cur_u, _p_pub_key_n);
		_result_q_i = pow_t_u_mod_n.modmul(_q, _p_pub_key_n);
	}

	function calc_tne_bn(
		Calc_tne_param memory _params
	) view private returns (BigNumber.instance[6] memory tau_list) {
		BigNumber.instance memory p_pub_key_n = BigNumber._new(_params.p_pub_key_n, false, false);
		BigNumber.instance memory p_pub_key_z = BigNumber._new(_params.p_pub_key_z, false, false);
		BigNumber.instance memory p_pub_key_s = BigNumber._new(_params.p_pub_key_s, false, false);

		for(uint8 i = 0; i < 4; i++) {
			tau_list[i] = calc_tne_result_tau_i(
				i, 
				_params,
				p_pub_key_n,
				p_pub_key_z,
				p_pub_key_s
			);
		}

		BigNumber.instance memory delta = getParamValue(keccak256(bytes("DELTA")), _params.r_keys, _params.r_values);
		if(_params.is_less) {
			delta = delta.bn_mul(minusOne);
		}

		tau_list[4] = calc_tne_result_tau_4(
			delta,
			_params.mj,
			p_pub_key_n,
			p_pub_key_z,
			p_pub_key_s
		);

		BigNumber.instance memory q = BigNumber._new(hex"0000000000000000000000000000000000000000000000000000000000000001", false, false);
		for(uint8 i = 0; i < 4; i++) {
			q = calc_tne_result_q_i(
				i,
				q,
				_params,
				p_pub_key_n
			);
		}

		BigNumber.instance memory alpha = BigNumber._new(_params.alpha, false, false);
		BigNumber.instance memory pow_s_alpha_mod_n = p_pub_key_s.prepare_modexp(alpha, p_pub_key_n);
		tau_list[5] = pow_s_alpha_mod_n.modmul(q, p_pub_key_n);
 	}

 	function calc_tne(
		Calc_tne_param memory _params
	) view public returns (bytes[6] memory _val, bool[6] memory _neg, uint[6] memory _bitlen) {
		BigNumber.instance[6] memory tau_list = calc_tne_bn(_params);

		for(uint8 i = 0; i < tau_list.length; i++) {
			_val[i] = tau_list[i].val;
			_neg[i] = tau_list[i].neg;
			_bitlen[i] = tau_list[i].bitlen;
		}
 	}

 	function verify_equality_result_rar(
 		Calc_teq_param memory _teq_params,
 		BigNumber.instance memory _two_596,
 		BigNumber.instance memory p_pub_key_n,
 		string[] memory _revealed_attrs,
 		bytes[] memory _revealed_attrs_values
 	)
 	view public returns (BigNumber.instance memory _verify_equality_result_rar) {
 		BigNumber.instance memory a_prime = BigNumber._new(_teq_params.a_prime, false, false);

		_verify_equality_result_rar = a_prime.prepare_modexp(_two_596, p_pub_key_n);

		for(uint256 i = 0; i < _revealed_attrs.length; i++) {
			bytes32 k = keccak256(bytes(_revealed_attrs[i]));

 			BigNumber.instance memory cur_r = getParamValue(k, _teq_params.p_pub_key_r_keys, _teq_params.p_pub_key_r_values);
 			BigNumber.instance memory encoded_value = BigNumber._new(_revealed_attrs_values[i], false, false);

 			BigNumber.instance memory rar_pow = cur_r.prepare_modexp(encoded_value, p_pub_key_n);
 			_verify_equality_result_rar = rar_pow.modmul(_verify_equality_result_rar, p_pub_key_n);
 			
 		}
 	}

 	function verify_equality_result_t1 (
 		Calc_teq_param memory _teq_params
 	)
 	view public returns (BigNumber.instance memory _verify_equality_result_t1 ) { 		
 		bytes memory teq_val;
		bool teq_neg;
		uint256 teq_bitlen;

		(teq_val, teq_neg, teq_bitlen) = calc_teq(_teq_params);

		_verify_equality_result_t1 = BigNumber._new(teq_val, teq_neg, false);
 	}

 	function verify_equality_result_z_inverted_t2(
 		bytes memory _p_pub_key_z,
 		bytes memory _p_pub_key_z_inverse,
 		BigNumber.instance memory p_pub_key_n,
 		BigNumber.instance memory _rar,
 		BigNumber.instance memory _c_hash
 	) 
 	view public returns (BigNumber.instance memory _verify_equality_result_z_inverted_t2) {
 		BigNumber.instance memory p_pub_key_z = BigNumber._new(_p_pub_key_z, false, false);
 		BigNumber.instance memory p_pub_key_z_inverse = BigNumber._new(_p_pub_key_z_inverse, false, false);

 		p_pub_key_z.prepare_modexp(p_pub_key_z_inverse, minusOne, p_pub_key_n);

 		_verify_equality_result_z_inverted_t2 = p_pub_key_z_inverse.bn_mul(_rar);
 		_verify_equality_result_z_inverted_t2 = _verify_equality_result_z_inverted_t2.prepare_modexp(_c_hash, p_pub_key_n);
 	}

 	function verify_equality(
 		Calc_teq_param memory _teq_params,
 		bytes memory _p_pub_key_z,
 		bytes memory _p_pub_key_z_inverse,
 		bytes memory _two_596,
 		string[] memory _revealed_attrs,
 		bytes[] memory _revealed_attrs_values,
 		bytes memory _c_hash
 	) view public returns (bytes memory, bool, uint) {
 		BigNumber.instance memory p_pub_key_n = BigNumber._new(_teq_params.p_pub_key_n, false, false);
 		BigNumber.instance memory two_596 = BigNumber._new(_two_596, false, false);
 		
 		BigNumber.instance memory rar = verify_equality_result_rar(
 			_teq_params, 
 			two_596, 
 			p_pub_key_n,
 			_revealed_attrs,
 			_revealed_attrs_values
 		);

 		BigNumber.instance memory t1 = verify_equality_result_t1(_teq_params);

 		BigNumber.instance memory c_hash = BigNumber._new(_c_hash, false, false);
 	 	BigNumber.instance memory t2 = verify_equality_result_z_inverted_t2(_p_pub_key_z, _p_pub_key_z_inverse, p_pub_key_n, rar, c_hash);
 		

 		BigNumber.instance memory t = t1.modmul(t2, p_pub_key_n);

 		return (t.val, t.neg, t.bitlen);	
 	}

 	function verify_ne_predicate_result_tau_i(
 		uint8 _i,
 		Calc_tne_param memory _tne_params,
 		BigNumber.instance memory _p_pub_key_n,
 		BigNumber.instance memory _c_hash,
 		string[] memory _cur_t_inverse_keys,
 		bytes[] memory _cur_t_inverse_values,
 		BigNumber.instance memory _tau_list_i
 	) view public returns (BigNumber.instance memory _result_tau_i) { 
 		bytes32 k = getIntStrHash(_i);

 		BigNumber.instance memory cur_t = getParamValue(k, _tne_params.t_keys, _tne_params.t_values);
		BigNumber.instance memory cur_t_inverse = getParamValue(k, _cur_t_inverse_keys, _cur_t_inverse_values);	

		cur_t.prepare_modexp(cur_t_inverse, minusOne, _p_pub_key_n);

		BigNumber.instance memory cur_t_inv_c_hash = cur_t_inverse.prepare_modexp(_c_hash, _p_pub_key_n);
		_result_tau_i = cur_t_inv_c_hash.modmul(_tau_list_i, _p_pub_key_n);
 	}

 	function verify_ne_predicate_result_tau_delta_intermediate(
 		Calc_tne_param memory _tne_params,
		BigNumber.instance memory _p_pub_key_n,
 		bytes memory _predicate_delta_prime_value,
 		BigNumber.instance memory _delta_prime,
 		BigNumber.instance memory _c_hash,
 		bytes memory _tau_delta_intermediate_inverse
 	) view public returns (BigNumber.instance memory _result_tau_delta_intermediate)  {
 		BigNumber.instance memory p_pub_key_z = BigNumber._new(_tne_params.p_pub_key_z, false, false);
 		BigNumber.instance memory predicate_delta_prime_value = BigNumber._new(_predicate_delta_prime_value, false, false);
 		BigNumber.instance memory tau_delta_intermediate_inverse = BigNumber._new(_tau_delta_intermediate_inverse, false, false);

 		_result_tau_delta_intermediate = p_pub_key_z.prepare_modexp(predicate_delta_prime_value, _p_pub_key_n);
 		_result_tau_delta_intermediate = _result_tau_delta_intermediate.modmul(_delta_prime, _p_pub_key_n);
 		_result_tau_delta_intermediate = _result_tau_delta_intermediate.prepare_modexp(_c_hash, _p_pub_key_n);

 		_result_tau_delta_intermediate.prepare_modexp(tau_delta_intermediate_inverse, minusOne, _p_pub_key_n);

 		_result_tau_delta_intermediate = tau_delta_intermediate_inverse;
 	}

 	function verify_ne_predicate_bn(
 		Calc_tne_param memory _tne_params,
 		Verify_ne_predicate_param memory _verify_ne_predicate_params
 	) view private returns (BigNumber.instance[6] memory) {
		BigNumber.instance memory p_pub_key_n = BigNumber._new(_tne_params.p_pub_key_n, false, false);
		BigNumber.instance memory c_hash = BigNumber._new(_verify_ne_predicate_params.c_hash, false, false);

 		BigNumber.instance[6] memory tau_list = calc_tne_bn(_tne_params);

		for(uint8 i = 0; i < 4; i++) {
 			tau_list[i] = verify_ne_predicate_result_tau_i(
 				i,
 				_tne_params,
 				p_pub_key_n,
 				c_hash,
 				_verify_ne_predicate_params.cur_t_inverse_keys,
 				_verify_ne_predicate_params.cur_t_inverse_values,
 				tau_list[i]
 			);
 		}

 		BigNumber.instance memory delta = getParamValue(keccak256(bytes("DELTA")), _tne_params.t_keys, _tne_params.t_values);
 		BigNumber.instance memory delta_prime = getParamValue(keccak256(bytes("DELTA")), _tne_params.t_keys, _tne_params.t_values);
		
		if(_tne_params.is_less) {
			BigNumber.instance memory proof_t_delta_inverse = BigNumber._new(_verify_ne_predicate_params.proof_t_delta_inverse, false, false);
			delta_prime.prepare_modexp(proof_t_delta_inverse, minusOne, p_pub_key_n);

			delta_prime = proof_t_delta_inverse;
		} 

		BigNumber.instance memory tau_delta_intermediate = verify_ne_predicate_result_tau_delta_intermediate(
			_tne_params,
			p_pub_key_n,
			_verify_ne_predicate_params.predicate_delta_prime_value,
			delta_prime,
			c_hash,
			_verify_ne_predicate_params.tau_delta_intermediate_inverse
		);


		tau_list[4] = tau_delta_intermediate.modmul(tau_list[4], p_pub_key_n);

		BigNumber.instance memory tau_5_intermediate = delta.prepare_modexp(c_hash, p_pub_key_n);
		BigNumber.instance memory tau_5_intermediate_inverse = BigNumber._new(_verify_ne_predicate_params.tau_5_intermediate_inverse, false, false);

		tau_5_intermediate.prepare_modexp(tau_5_intermediate_inverse, minusOne, p_pub_key_n);

		tau_list[5] = tau_5_intermediate_inverse.modmul(tau_list[5], p_pub_key_n);

		return tau_list;
 	}

 	function verify_ne_predicate(
 		Calc_tne_param memory _tne_params,
 		Verify_ne_predicate_param memory _verify_ne_predicate_params
 	) view public returns (bytes[6] memory _val, bool[6] memory _neg, uint[6] memory _bitlen) {
 		BigNumber.instance[6] memory tau_list = verify_ne_predicate_bn(_tne_params, _verify_ne_predicate_params);

		for(uint8 i = 0; i < tau_list.length; i++) {
			_val[i] = tau_list[i].val;
			_neg[i] = tau_list[i].neg;
			_bitlen[i] = tau_list[i].bitlen;
		}
 	}


}