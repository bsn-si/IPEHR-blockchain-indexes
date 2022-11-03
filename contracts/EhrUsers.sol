// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.4;

import "./EhrRestrictable.sol";
import "./EhrAccess.sol";
import "./SignChecker.sol";

contract EhrUsers is EhrRestrictable, EhrAccess {
    enum Role { Patient, Doctor }

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

  mapping (address => User) public users;
  mapping (bytes32  => bytes32) public ehrUsers; // userId -> EHRid
  mapping (bytes32 => UserGroup) public userGroups;

  ///
  function setEhrUser(
    bytes32 userId, 
    bytes32 ehrId,
    uint nonce, 
    address signer, 
    bytes memory signature
  ) 
    external onlyAllowed(msg.sender) checkNonce(signer, nonce)
  {
    // Signature verification
    bytes32 payloadHash = keccak256(abi.encode("setEhrUser", userId, ehrId, nonce));
    require(SignChecker.signCheck(payloadHash, signer, signature), "SIG");

    ehrUsers[userId] = ehrId;
  }

  ///
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

    // Checking user existence
    require(users[userAddr].id == bytes32(0), "AEX");

    // Signature verification
    bytes32 payloadHash = keccak256(abi.encode("userAdd", userAddr, id, systemID, role, pwdHash, nonce));
    require(SignChecker.signCheck(payloadHash, signer, signature), "SIG");

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

  function groupCreate(
      bytes32 groupID, 
      bytes calldata description, 
      uint nonce, 
      address signer, 
      bytes calldata signature
  ) external onlyAllowed(msg.sender) checkNonce(signer, nonce) {

    // Checking user existence
    require(users[signer].id != bytes32(0), "NFD");

    // Signature verification
    bytes32 payloadHash = keccak256(abi.encode("groupCreate", groupID, description, nonce));
    require(SignChecker.signCheck(payloadHash, signer, signature), "SIG");

    // Checking group absence
    require(userGroups[groupID].description.length == 0, "AEX");

    // Creating a group
    userGroups[groupID].description = description;
    userGroups[groupID].members[signer] = AccessLevel.Owner;

    // Adding a groupID to a user's group list
    users[signer].groups.push(groupID);
  }

  function groupAddUser(
      bytes32 groupID, 
      address addingUserAddr, 
      AccessLevel level, 
      bytes calldata keyEncrypted, 
      uint nonce, 
      address signer, 
      bytes calldata signature
  ) external checkNonce(signer, nonce) {

    // Checking user existence
    require(users[addingUserAddr].id != bytes32(0), "NFD");

    // Signature verification
    bytes32 payloadHash = keccak256(abi.encode("groupAddUser", groupID, addingUserAddr, level, keyEncrypted, nonce));
    require(SignChecker.signCheck(payloadHash, signer, signature), "SIG");

    // Checking access rights
    require(userGroups[groupID].members[signer] == AccessLevel.Owner || 
        userGroups[groupID].members[signer] == AccessLevel.Admin, "DNY");

    // Adding a user to a group
    userGroups[groupID].members[addingUserAddr] = level;

    // Adding the group's secret key
    accessStore[keccak256(abi.encode(users[addingUserAddr].id, groupID))] = Access({
        level: level,
        keyEncrypted: keyEncrypted
    });

    // Adding a groupID to a user's group list
    users[addingUserAddr].groups.push(groupID);
  }

  function groupRemoveUser(
      bytes32 groupID, 
      address removingUserAddr, 
      uint nonce, 
      address signer, 
      bytes calldata signature
  ) external checkNonce(signer, nonce) {

    // Checking user existence
    require(users[removingUserAddr].id != bytes32(0), "NFD");

    // Signature verification
    bytes32 payloadHash = keccak256(abi.encode("groupRemoveUser", groupID, removingUserAddr, nonce));
    require(SignChecker.signCheck(payloadHash, signer, signature), "SIG");

    // Checking access rights
    require(userGroups[groupID].members[signer] == AccessLevel.Owner ||
        userGroups[groupID].members[signer] == AccessLevel.Admin, "DNY");

    // Removing a user from a group
    userGroups[groupID].members[removingUserAddr] = AccessLevel.NoAccess;

    // Removing a group's access key
    accessStore[keccak256(abi.encode(users[removingUserAddr].id, groupID))] = Access({
      level: AccessLevel.NoAccess,
      keyEncrypted: bytes("")
    });

    //TODO Delete groupID from the list of user groups
  }
}

