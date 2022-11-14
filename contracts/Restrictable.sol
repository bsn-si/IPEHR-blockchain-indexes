// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

contract Restrictable is Ownable {
  mapping (address => bool) public allowedChange;
  mapping (address => uint) public nonces;

  modifier onlyAllowed(address _addr) {
    require(allowedChange[_addr] == true, "Not allowed");
    _;
  }

  function setAllowed(address addr, bool allowed) external onlyOwner() {
    allowedChange[addr] = allowed;
  }

  function signCheck(
      bytes32 payloadHash, 
      address signer,
      bytes calldata signature
  ) 
    internal returns (bool) 
  {
    nonces[signer]++;
    return SignatureChecker.isValidSignatureNow(
      signer, 
      keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash, nonces[signer])), 
      signature
    );
  }
}
