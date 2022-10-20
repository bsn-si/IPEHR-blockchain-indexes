pragma solidity ^0.8.4;
import "./EhrRestrictable.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

contract EhrUsers is EhrRestrictable {
    enum Role { Patient, Doctor }
    enum AccessLevel { Owner, Admin, Read }

  struct Access {
    AccessLevel level;
    bytes       keyEncrypted;
    bool        isUser;
  }

  struct User {
    bytes32   id;
    bytes32   systemID;
    Role      role;
    bytes32[] groups;
    bytes     pwdHash;
    bool      isUser;
  }

  struct UserGroup {
    bytes32   groupID;
    string    description;
    bool      isGroup;
    mapping(address => Access) members;
  }

  mapping (address => User) users;
  mapping(bytes32 => UserGroup) userGroups;

  function userAdd(address userAddr, bytes32 id, Role role, bytes calldata pwdHash, uint deadline, address signer, bytes memory signature) external
    onlyAllowed(msg.sender) beforeDeadline(deadline) {
    bytes32 payloadHash = keccak256(abi.encode("userAdd", id, role, pwdHash, deadline));
    bytes32 messageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash));
    require(SignatureChecker.isValidSignatureNow(signer, messageHash, signature), "DND");
    users[userAddr].id = id;
    users[userAddr].pwdHash = pwdHash;
    users[userAddr].role = role;
    users[userAddr].isUser = true;
  }

  function getUserPasswordHash(address userAddr) public view returns (bytes memory) {
    if (!users[userAddr].isUser) revert("NFD");
    return users[userAddr].pwdHash;
  }

  function groupCreate(bytes32 groupID, string calldata description, uint deadline, address signer, bytes calldata signature) external
    onlyAllowed(msg.sender) beforeDeadline(deadline) onlySigned(signer, signature) {
    require(SignatureChecker.isValidSignatureNow(signer, keccak256(msg.data), signature), "DND");
    require(userGroups[groupID].isGroup == true, "AEX");
    userGroups[groupID].isGroup = true;
    userGroups[groupID].description = description;
    userGroups[groupID].members[signer].level = AccessLevel.Owner;
  }

  function groupAddUser(bytes32 groupID, address addingUserAddr, address signer, bytes calldata signature) external onlySigned(signer, signature) beforeDeadline(block.timestamp) {
    require(userGroups[groupID].members[signer].level == AccessLevel.Owner ||
      userGroups[groupID].members[signer].level == AccessLevel.Admin, "DND");
    userGroups[groupID].members[addingUserAddr].level = AccessLevel.Read;
    userGroups[groupID].members[addingUserAddr].isUser = true;
  }

  function groupRemoveUser(bytes32 groupID, address removingUserAddr, address signer, bytes calldata signature) onlySigned(signer, signature) beforeDeadline(block.timestamp) external {
    require(SignatureChecker.isValidSignatureNow(signer, keccak256(msg.data), signature), "DND");
    require(userGroups[groupID].members[signer].level == AccessLevel.Owner ||
      userGroups[groupID].members[signer].level == AccessLevel.Admin, "DND");
      userGroups[groupID].members[removingUserAddr].isUser = false;
  }
}