// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./libraries/Attributes.sol";
import "./Access.sol";

contract Users is Access {
    enum Role { Patient, Doctor }

    struct User {
      bytes32   id;
      bytes32   systemID;
      Role      role;
      bytes     pwdHash;
    }

    struct UserGroup {
      mapping(Attributes.Code => bytes) attrs;
      mapping(address => AccessLevel) members;
      uint membersCount;
    }

  mapping (address => User) public users;
  mapping (bytes32 => bytes32) public ehrUsers; // userID -> ehrID
  mapping (bytes32 => UserGroup) userGroups; // groupIdHash => UserGroup

  ///
  function setEhrUser(bytes32 userId, bytes32 ehrId, address signer, bytes calldata signature) 
    external onlyAllowed(msg.sender)
  {
    signCheck(signer, signature);
    require(ehrUsers[userId] == bytes32(0), "AEX");
    ehrUsers[userId] = ehrId;
  }

  ///
  function userNew(
    address userAddr, 
    bytes32 id, 
    bytes32 systemID, 
    Role role, 
    bytes calldata pwdHash, 
    address signer, 
    bytes calldata signature
  ) external onlyAllowed(msg.sender) {

    signCheck(signer, signature);

    // Checking user existence
    require(users[userAddr].id == bytes32(0), "AEX");

    users[userAddr] = User({
      id: id, 
      systemID: systemID,
      role: role, 
      pwdHash: pwdHash
    });
  }

  struct UserGroupCreateParams {
      bytes32     groupIdHash;
      Attributes.Attribute[] attrs;
      address     signer;
      bytes       signature;
  }

  ///
  function userGroupCreate(UserGroupCreateParams calldata p) 
      external onlyAllowed(msg.sender) 
  {
    signCheck(p.signer, p.signature);

    // Checking user existence
    require(users[p.signer].id != bytes32(0), "NFD");

    // Checking group absence
    require(userGroups[p.groupIdHash].membersCount == 0, "AEX");

    // Creating a group
    userGroups[p.groupIdHash].members[p.signer] = AccessLevel.Owner;
    userGroups[p.groupIdHash].membersCount++;

    for(uint i; i < p.attrs.length; i++){
      userGroups[p.groupIdHash].attrs[p.attrs[i].code] = p.attrs[i].value;
    }

    // Adding a groupID to a user's group list
    accessStore[keccak256(abi.encode(p.groupIdHash, AccessKind.UserGroup))].push(Object({
      idHash: p.groupIdHash,
      idEncr: Attributes.get(p.attrs, Attributes.Code.IDEncr),
      keyEncr: Attributes.get(p.attrs, Attributes.Code.KeyEncr),
      level: AccessLevel.Owner
    }));
  }

  struct GroupAddUserParams {
    bytes32 groupIdHash;
    address addingUserAddr;
    AccessLevel level;
    bytes idEncr;
    bytes keyEncr;
    address signer;
    bytes signature;
  }

  ///
  function groupAddUser(GroupAddUserParams calldata p) 
    external
  {
    signCheck(p.signer, p.signature);

    // Checking user existence
    require(users[p.addingUserAddr].id != bytes32(0), "NFD");

    // Checking user not in group already
    // TODO

    // Checking access rights
    require(userGroups[p.groupIdHash].members[p.signer] == AccessLevel.Owner || 
        userGroups[p.groupIdHash].members[p.signer] == AccessLevel.Admin, "DNY");

    // Adding a user to a group
    userGroups[p.groupIdHash].members[p.addingUserAddr] = p.level;
    userGroups[p.groupIdHash].membersCount++;

    // Adding the group's secret key
    accessStore[keccak256(abi.encode(users[p.addingUserAddr].id, AccessKind.UserGroup))].push(Object({
      idHash: p.groupIdHash,
      idEncr: p.idEncr,
      keyEncr: p.keyEncr,
      level: p.level
    }));
  }

  ///
  function groupRemoveUser(
      bytes32 groupIdHash, 
      address removingUserAddr, 
      address signer, 
      bytes calldata signature
  ) 
      external
  {
    signCheck(signer, signature);

    // Checking user existence
    require(users[removingUserAddr].id != bytes32(0), "NFD");

    // Checking access rights
    require(userGroups[groupIdHash].members[signer] == AccessLevel.Owner ||
        userGroups[groupIdHash].members[signer] == AccessLevel.Admin, "DNY");

    // Removing a user from a group
    userGroups[groupIdHash].members[removingUserAddr] = AccessLevel.NoAccess;
    userGroups[groupIdHash].membersCount--;

    // Removing a group's access key
    bytes32 userIdHash = keccak256(abi.encode(users[removingUserAddr].id, AccessKind.UserGroup));
    for(uint i; i < accessStore[userIdHash].length; i++) {
      if (accessStore[userIdHash][i].idHash == groupIdHash) {
        accessStore[userIdHash][i].idHash = bytes32(0);
        accessStore[userIdHash][i].idEncr = new bytes(0);
        accessStore[userIdHash][i].keyEncr = new bytes(0);
        accessStore[userIdHash][i].level = AccessLevel.NoAccess;
        return;
      }
    }

    revert("NFD");

    //TODO Delete groupID from the list of user groups
  }

}

