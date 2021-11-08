pragma solidity >=0.8.7 <0.9.0;

import "./BigNumber.sol";

contract Verify {
	using BigNumber for *;

	function calc_teq(
		bytes memory p_pub_key_n,
		uint256 p_pub_key_n_bits,
		bytes memory p_pub_key_s,
		bytes memory p_pub_key_rctxt,

		bytes[] memory p_pub_key_r_unrevealed_attrs,
		string[] memory unrevealed_attrs
	) public returns (bytes memory, bool, uint) {
		BigNumber.instance memory bn_p_pub_key_n = BigNumber.instance(p_pub_key_n, false, p_pub_key_n_bits);

		return (bn_p_pub_key_n.val, bn_p_pub_key_n.neg, bn_p_pub_key_n.bitlen);
	}
	
}