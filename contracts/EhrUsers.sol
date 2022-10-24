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

  mapping (address => User) public users;
  mapping (bytes32 => UserGroup) public userGroups;
  mapping (bytes32 => Access) public groupAccess;

  function userAdd(
    address userAddr, 
    bytes32 id, 
    bytes32 systemID, 
    Role role, 
    bytes calldata pwdHash, 
    uint nonce, 
    address signer, 
    bytes memory signature
  ) external onlyAllowed(msg.sender) checkNonce(signer, nonce) {

    require(users[userAddr].id == bytes32(0), "AEX");

    bytes32 payloadHash = keccak256(abi.encode("userAdd", userAddr, id, systemID, role, pwdHash, nonce));
    require(SignChecker.signCheck(payloadHash, signer, signature), "DNY");

    users[userAddr] = User({
        id: id, 
        systemID: systemID,
        role: role, 
        groups: new bytes32[](0),
        pwdHash: pwdHash 
    });

  }

  function getUserPasswordHash(address userAddr) public view returns (bytes memory) {
    require(users[userAddr].id != bytes32(0), "NFD");
    return users[userAddr].pwdHash;
  }

  function groupCreate(bytes32 groupID, bytes calldata description, uint nonce, address signer, bytes calldata signature) external
    onlyAllowed(msg.sender) checkNonce(signer, nonce) {
    bytes32 payloadHash = keccak256(abi.encode("groupCreate", groupID, description, nonce));
    require(SignChecker.signCheck(payloadHash, signer, signature), "DNY");
    require(userGroups[groupID].description.length == 0, "AEX");
    userGroups[groupID].description = description;
    userGroups[groupID].members[signer] = AccessLevel.Owner;
  }

  function groupAddUser(bytes32 groupID, address addingUserAddr, AccessLevel level, bytes calldata keyEncrypted, uint nonce, address signer, bytes calldata signature)
    external checkNonce(signer, nonce) {
    bytes32 payloadHash = keccak256(abi.encode("groupAddUser", groupID, addingUserAddr, level, keyEncrypted, nonce));
    require(SignChecker.signCheck(payloadHash, signer, signature), "DNY");
    require(userGroups[groupID].members[signer] == AccessLevel.Owner ||
      userGroups[groupID].members[signer] == AccessLevel.Admin, "DNY");
    require(users[addingUserAddr].id.length > 0, "NFD");
    userGroups[groupID].members[addingUserAddr] = level;
    groupAccess[keccak256(abi.encode(users[addingUserAddr].id, groupID))] = Access({
        level: level,
        keyEncrypted: keyEncrypted
    });
  }

  function groupRemoveUser(bytes32 groupID, address removingUserAddr, uint nonce, address signer, bytes calldata signature)
    external checkNonce(signer, nonce) {
    bytes32 payloadHash = keccak256(abi.encode("groupRemoveUser", groupID, removingUserAddr, nonce));
    require(SignChecker.signCheck(payloadHash, signer, signature), "DNY");
    require(userGroups[groupID].members[signer] == AccessLevel.Owner ||
      userGroups[groupID].members[signer] == AccessLevel.Admin, "DNY");
    require(users[removingUserAddr].id.length > 0, "NFD");
    userGroups[groupID].members[removingUserAddr] = AccessLevel.NoAccess;
    groupAccess[keccak256(abi.encode(users[removingUserAddr].id, groupID))] = Access({
      level: AccessLevel.NoAccess,
      keyEncrypted: bytes("")
    });
  }
}

