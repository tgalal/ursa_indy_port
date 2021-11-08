pragma solidity >=0.8.7 <0.9.0;

import "./BigNumber.sol";

contract Verify {
	using BigNumber for *;

	struct Calc_teq_param {
		bytes p_pub_key_n;
		uint256 p_pub_key_n_bits;

		/*bytes p_pub_key_s;
		bytes p_pub_key_rctxt;

		bytes[] r_unrevealed_attrs_values;
		string[] r_unrevealed_attrs_keys;

		bytes[] m_revealed_attrs_values;
		string[] m_revealed_attrs_keys;

		*/bytes a_prime;
		uint256 a_prime_bits;

		bytes e;
		uint256 e_bits;

		/*bytes v;
		uint256 v_bits;

		bytes mtilde;
		uint256 mtilde_bits;*/
	}

	function calc_teq(Calc_teq_param memory _params
		
	) public returns (bytes memory, bool, uint) {
		BigNumber.instance memory p_pub_key_n = BigNumber.instance(_params.p_pub_key_n, false, _params.p_pub_key_n_bits);
		BigNumber.instance memory a_prime = BigNumber.instance(_params.a_prime, false, _params.a_prime_bits);
		BigNumber.instance memory e = BigNumber.instance(_params.e, false, _params.e_bits);

		BigNumber.instance memory res = a_prime.prepare_modexp(e, p_pub_key_n);


		//bn_p_pub_key_n.prepare_modexp()

		return (res.val, res.neg, res.bitlen);
	}
	
}