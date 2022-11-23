// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

contract Restrictable is Ownable {
  mapping (address => bool) public allowedChange;
  mapping (address => uint) public nonces;

  constructor() {
    allowedChange[msg.sender] = true;
  }

  modifier onlyAllowed(address _addr) {
    require(allowedChange[_addr] == true, "Not allowed");
    _;
  }

  function signCheck(address signer, bytes calldata signature) internal {
    nonces[signer]++;

    bool valid = SignatureChecker.isValidSignatureNow(
      signer, 
      keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(msg.data[:msg.data.length - 97]), nonces[signer])), 
      signature
    );
  
    require(valid == true, "SIG");
  }

  function setAllowed(address addr, bool allowed) external onlyOwner() {
    allowedChange[addr] = allowed;
  }
}
