pragma solidity >=0.4.20 <0.6;


import "./BigNumber.sol";

contract BigNumberTest {
	using BigNumber for *;

	function returnBigNumber(
		bytes memory _val,
		uint256 _bits
	) public returns (bytes memory, bool, uint) {
		BigNumber.instance memory bn_val = BigNumber.instance(_val, false, _bits);

		return (bn_val.val, bn_val.neg, bn_val.bitlen);
	}
	
}	