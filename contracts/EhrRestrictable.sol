pragma solidity ^0.8.4;
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

contract EhrRestrictable is Ownable {
  mapping (address => bool) public allowedChange;

  modifier onlyAllowed(address _addr) {
    require(allowedChange[_addr] == true, "Not allowed");
    _;
  }

  modifier beforeDeadline(uint _deadline) {
    require(block.timestamp < _deadline, "TMT" );
    _;
  }

  modifier onlySigned(address signer, bytes memory signature) {
    require(SignatureChecker.isValidSignatureNow(signer, keccak256(msg.data), signature), "DND");
    _;
  }

  function setAllowed(address addr, bool allowed) external onlyOwner() {
    allowedChange[addr] = allowed;
  }
}