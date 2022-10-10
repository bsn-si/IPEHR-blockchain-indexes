pragma solidity ^0.8.4;
import "@openzeppelin/contracts/access/Ownable.sol";

contract EhrRestrictable is Ownable {
  mapping (address => bool) public allowedChange;

  modifier onlyAllowed(address _addr) {
    require(allowedChange[_addr] == true, "Not allowed");
    _;
  }

  function setAllowed(address addr, bool allowed) external onlyOwner() {
    allowedChange[addr] = allowed;
  }
}