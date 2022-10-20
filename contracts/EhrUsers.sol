pragma solidity ^0.8.4;
import "./EhrRestrictable.sol";
import "./SignChecker.sol";

contract EhrUsers is EhrRestrictable {
    enum Role { Patient, Doctor }
    enum AccessLevel { NoAccess, Owner, Admin, Read }

  struct User {
    bytes32   id;
    bytes32   systemID;
    Role      role;
    bytes32[] groups;
    bytes     pwdHash;
  }

  struct UserGroup {
    bytes    description;
    mapping(address => AccessLevel) members;
  }

  struct Access {
    AccessLevel   level;
    bytes       keyEncrypted;
}

  mapping (address => User) users;
  mapping (bytes32 => UserGroup) userGroups;
  mapping (bytes32 => Access) public groupAccess;

  function userAdd(address userAddr, bytes32 id, Role role, bytes calldata pwdHash, uint deadline, address signer, bytes memory signature) external
    onlyAllowed(msg.sender) beforeDeadline(deadline) {
    bytes32 payloadHash = keccak256(abi.encode("userAdd", id, role, pwdHash, deadline));
    require(SignChecker.signCheck(payloadHash, signer, signature), "DND");
    users[userAddr] = User({
        id: id, 
        systemID: bytes32(0), 
        role: role, 
        groups: new bytes32[](0), 
        pwdHash: pwdHash 
    });
  }

  function getUserPasswordHash(address userAddr) public view returns (bytes memory) {
    if (users[userAddr].id == bytes32(0)) revert("NFD");
    return users[userAddr].pwdHash;
  }

  function groupCreate(bytes32 groupID, bytes calldata description, uint deadline, address signer, bytes calldata signature) external
    onlyAllowed(msg.sender) beforeDeadline(deadline) {
    bytes32 payloadHash = keccak256(abi.encode("groupCreate", groupID, description, deadline));
    require(SignChecker.signCheck(payloadHash, signer, signature), "DND");
    require(userGroups[groupID].description.length == 0, "AEX");
    userGroups[groupID].description = description;
    userGroups[groupID].members[signer] = AccessLevel.Owner;
  }

  function groupAddUser(bytes32 groupID, address addingUserAddr, AccessLevel level, bytes calldata keyEncrypted, address signer, bytes calldata signature) external beforeDeadline(block.timestamp) {
    bytes32 payloadHash = keccak256(abi.encode("groupAddUser", groupID, addingUserAddr, level, keyEncrypted));

    require(SignChecker.signCheck(payloadHash, signer, signature), "DND");
    require(userGroups[groupID].members[signer] == AccessLevel.Owner ||
      userGroups[groupID].members[signer] == AccessLevel.Admin, "DND");
    require(users[addingUserAddr].id.length > 0, "NFD");
    userGroups[groupID].members[addingUserAddr] = level;
    groupAccess[keccak256(abi.encode(users[addingUserAddr].id, groupID))] = Access({
        level: level,
        keyEncrypted: keyEncrypted
    });
  }

  function groupRemoveUser(bytes32 groupID, address removingUserAddr, address signer, bytes calldata signature) beforeDeadline(block.timestamp) external {
    bytes32 payloadHash = keccak256(abi.encode("groupRemoveUser", groupID, removingUserAddr));
    require(SignChecker.signCheck(payloadHash, signer, signature), "DND");
    require(userGroups[groupID].members[signer] == AccessLevel.Owner ||
      userGroups[groupID].members[signer] == AccessLevel.Admin, "DND");
    require(users[removingUserAddr].id.length > 0, "NFD");
    userGroups[groupID].members[removingUserAddr] = AccessLevel.NoAccess;
    groupAccess[keccak256(abi.encode(users[removingUserAddr].id, groupID))] = Access({
      level: AccessLevel.NoAccess,
      keyEncrypted: bytes("0")
    });
  }
}
