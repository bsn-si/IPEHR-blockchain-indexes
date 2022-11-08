// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;
import "@openzeppelin/contracts/access/Ownable.sol";

contract Restrictable is Ownable {
  mapping (address => bool) public allowedChange;
  mapping (address => uint) public nonces;

  modifier onlyAllowed(address _addr) {
    require(allowedChange[_addr] == true, "Not allowed");
    _;
  }

  modifier checkNonce(address _addr, uint nonce) {
      require(nonces[_addr] == nonce - 1, "NON");
      nonces[_addr]++;
      _;
  }

  function setAllowed(address addr, bool allowed) external onlyOwner() {
    allowedChange[addr] = allowed;
  }
}

