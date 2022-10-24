pragma solidity ^0.8.4;

import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

library SignChecker {
  function signCheck(
      bytes32 payloadHash, 
      address signer, 
      bytes memory signature
  ) external view returns (bool) {
    bytes32 messageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash));
    return SignatureChecker.isValidSignatureNow(signer, messageHash, signature);
  }
}
