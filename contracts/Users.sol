// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./libraries/Attributes.sol";
import "./Access.sol";

contract Users is AccessStore {
    enum Role { Patient, Doctor }

    struct User {
      bytes32   IDHash;
      Role      role;
      Attributes.Attribute[] attrs;
    }

    struct GroupMember {
      bytes32 userIDHash;
      bytes userIDEncr;    // userIDs encrypted by group key
    }

    struct UserGroup {
      Attributes.Attribute[] attrs;
      GroupMember[] members;  
    }

  mapping (address => User) users;
  mapping (bytes32 => bytes32) public ehrUsers; // userID -> ehrID
  mapping (bytes32 => UserGroup) userGroups;    // groupIdHash => UserGroup

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
    address addr, 
    bytes32 IDHash,        // sha3(userID+systemID) 
    Role role, 
    Attributes.Attribute[] calldata attrs,
    address signer, 
    bytes calldata signature
  ) external onlyAllowed(msg.sender) {

    signCheck(signer, signature);

    // Checking user existence
    require(users[addr].IDHash == bytes32(0), "AEX");

    users[addr].IDHash = IDHash;
    users[addr].role = role;

    for (uint i; i < attrs.length; i++) {
      if (attrs[i].code == Attributes.Code.Timestamp) continue;
      users[addr].attrs.push(attrs[i]);
    }

    // Set timestamp
    users[addr].attrs.push(Attributes.Attribute({
      code: Attributes.Code.Timestamp,
      value: abi.encodePacked(block.timestamp)
    }));
  }

  ///
  function getUser(address addr) external view returns(User memory) {
    return(users[addr]);
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
    require(users[p.signer].IDHash != bytes32(0), "NFD");

    // Checking group absence
    require(userGroups[p.groupIdHash].attrs.length == 0, "AEX");

    // Creating a group
    for (uint i; i < p.attrs.length; i++) {
      userGroups[p.groupIdHash].attrs.push(p.attrs[i]);
    }

    // Adding a groupID to a user's group list
    setAccess(keccak256(abi.encode(users[p.signer].IDHash, AccessKind.UserGroup)), Access({
      idHash: p.groupIdHash,
      idEncr: Attributes.get(p.attrs, Attributes.Code.IDEncr),
      keyEncr: Attributes.get(p.attrs, Attributes.Code.KeyEncr),
      level: AccessLevel.Owner
    }));
  }

  struct GroupAddUserParams {
    bytes32 groupIDHash;
    bytes32 userIDHash;
    AccessLevel level;
    bytes userIDEncr;       // userID encrypted by group key
    bytes keyEncr;          // group key encrypted by adding user public key
    address signer;
    bytes signature;
  }

  ///
  function groupAddUser(GroupAddUserParams calldata p) external
  {
    signCheck(p.signer, p.signature);

    // Checking access rights
    Access memory signerAccess = userAccess(users[p.signer].IDHash, AccessKind.UserGroup, p.groupIDHash);
    require(signerAccess.level == AccessLevel.Owner || signerAccess.level == AccessLevel.Admin, "DNY");

    // Checking group is exist
    require(userGroups[p.groupIDHash].attrs.length > 0, "NFD");
    
    // Checking user not in group already
    for (uint i; i < userGroups[p.groupIDHash].members.length; i++) {
      if (userGroups[p.groupIDHash].members[i].userIDHash == p.userIDHash) revert("AEX");
    }

    // Adding a user to a group
    userGroups[p.groupIDHash].members.push(GroupMember({
      userIDHash: p.userIDHash,
      userIDEncr: p.userIDEncr
    }));

    // Adding the group's secret key
    setAccess(keccak256(abi.encode(p.userIDHash, AccessKind.UserGroup)), Access({
      idHash: p.groupIDHash,
      idEncr: signerAccess.idEncr,
      keyEncr: p.keyEncr,
      level: p.level
    }));
  }

  ///
  function groupRemoveUser(
      bytes32 groupIDHash, 
      bytes32 userIDHash, 
      address signer, 
      bytes calldata signature
  ) 
      external
  {
    signCheck(signer, signature);

    // Checking access rights
    Access memory signerAccess = userAccess(users[signer].IDHash, AccessKind.UserGroup, groupIDHash);
    require(signerAccess.level == AccessLevel.Owner || signerAccess.level == AccessLevel.Admin, "DNY");

    // Removing a user from a group
    for(uint i; i < userGroups[groupIDHash].members.length; i++) {
      if (userGroups[groupIDHash].members[i].userIDHash == userIDHash) {
          userGroups[groupIDHash].members[i] = userGroups[groupIDHash].members[userGroups[groupIDHash].members.length-1];
          userGroups[groupIDHash].members.pop();
      }
    }

    // Removing a group's access key
    require(setAccess(keccak256(abi.encode(userIDHash, AccessKind.UserGroup)), ZeroAccess) == 1,"NFD");
  }

  function userGroupGetByID(bytes32 groupIdHash) external view returns(UserGroup memory) {
    return(userGroups[groupIdHash]);
  }
}

