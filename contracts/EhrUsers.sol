pragma solidity ^0.8.4;
import "./EhrRestrictable.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

contract EhrUsers is EhrRestrictable {
    enum Role { Patient, Doctor }
    enum AccessLevel { Owner, Admin, Read }

  struct Access {
    AccessLevel level;
    bytes       keyEncrypted;
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

  function userAdd(address userAddr, bytes32 id, Role role, bytes calldata pwdHash, uint deadline, address signer, bytes memory signature) external onlyAllowed(msg.sender) beforeDeadline(block.timestamp) {
    require(block.timestamp < deadline, "TMT" );
    require(SignatureChecker.isValidSignatureNow(signer, keccak256(msg.data), signature), "DND");
    users[userAddr].id = id;
    users[userAddr].pwdHash = pwdHash;
    users[userAddr].role = role;
    users[userAddr].isUser = true;
  }

  function getUserPasswordHash(address userAddr) public view returns (bytes memory) {
    if (!users[userAddr].isUser) revert("NFD");
    return users[userAddr].pwdHash;
  }

  function groupCreate(bytes32 groupID, string calldata description, address signer, bytes calldata signature) external onlyAllowed(msg.sender) {
    if (userGroups[groupID].isGroup) revert ("AEX");
    userGroups[groupID].isGroup = true;
    userGroups[groupID].description = description;
    userGroups[groupID].members[signer].level = AccessLevel.Owner;
  }

  function groupAddUser(bytes32 groupID, address addingUserAddr, address signer, bytes calldata signature) external {
    require(userGroups[groupID].members[signer].level == AccessLevel.Owner ||
      userGroups[groupID].members[signer].level == AccessLevel.Admin, "DND");
  }

  function groupRemoveUser(bytes32 groupID, address removingUserAddr, address signer, bytes calldata signature) external {
    require(userGroups[groupID].members[signer].level == AccessLevel.Owner ||
      userGroups[groupID].members[signer].level == AccessLevel.Admin, "DND");
  }
}