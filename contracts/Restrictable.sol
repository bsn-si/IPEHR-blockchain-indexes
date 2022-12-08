// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

contract Restrictable {
  address private _owner;
  mapping (address => bool) public allowedChange;
  mapping (address => uint) public nonces;

  constructor() {
    _owner = msg.sender;
    allowedChange[msg.sender] = true;
  }

  modifier onlyOwner() {
    _checkOwner();
    _;
  }

  modifier onlyAllowed(address _addr) {
    require(allowedChange[_addr] == true, "Not allowed");
    _;
  }

  function _checkOwner() internal view {
    require(_owner == msg.sender, "OWN");
  }

  function setAllowed(address addr, bool allowed) public onlyOwner {
    allowedChange[addr] = allowed;
  }

  function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "WTP");
        _transferOwnership(newOwner);
    }

    function _transferOwnership(address newOwner) internal {
        _owner = newOwner;
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
}
