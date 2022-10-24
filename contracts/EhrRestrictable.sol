pragma solidity ^0.8.4;
import "@openzeppelin/contracts/access/Ownable.sol";

contract EhrRestrictable is Ownable {
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

