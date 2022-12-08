// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./libraries/Attributes.sol";

import "./interfaces/IAccessStore.sol";
import "./interfaces/IUsers.sol";

import "./Restrictable.sol";
import "./ImmutableState.sol";

contract Users is IUsers, ImmutableState, Restrictable {
  mapping (address => User) usersStore;
  mapping (bytes32 => UserGroup) userGroups;    // groupIdHash => UserGroup

  constructor(address _accessStore) ImmutableState(_accessStore, address(this)) {}

  ///
  function userNew(
    address addr, 
    bytes32 IDHash,        // sha3(userID+systemID) 
    Role role, 
    Attributes.Attribute[] calldata attrs,
    address signer, 
    bytes calldata signature
  ) 
    external onlyAllowed(msg.sender) 
  {
    signCheck(signer, signature);

    // Checking user existence
    require(usersStore[addr].IDHash == bytes32(0), "AEX");

    usersStore[addr].IDHash = IDHash;
    usersStore[addr].role = role;

    for (uint i; i < attrs.length; i++) {
      if (attrs[i].code == Attributes.Code.Timestamp) continue;
      usersStore[addr].attrs.push(attrs[i]);
    }

    // Set timestamp
    usersStore[addr].attrs.push(Attributes.Attribute({
      code: Attributes.Code.Timestamp,
      value: abi.encodePacked(block.timestamp)
    }));
  }

  ///
  function getUser(address addr) external view returns(User memory) {
    return usersStore[addr];
  }

  ///
  function userGroupCreate(
    bytes32 groupIdHash, 
    Attributes.Attribute[] calldata attrs, 
    address signer,
    bytes calldata signature
  ) 
      external onlyAllowed(msg.sender) 
  {
    signCheck(signer, signature);

    // Checking user existence
    require(usersStore[signer].IDHash != bytes32(0), "NFD");

    // Checking group absence
    require(userGroups[groupIdHash].attrs.length == 0, "AEX");

    // Creating a group
    for (uint i; i < attrs.length; i++) {
      userGroups[groupIdHash].attrs.push(attrs[i]);
    }

    // Adding a groupID to a user's group list
    IAccessStore(accessStore).setAccess(keccak256(abi.encode(usersStore[signer].IDHash, IAccessStore.AccessKind.UserGroup)), IAccessStore.Access({
      idHash: groupIdHash,
      idEncr: Attributes.get(attrs, Attributes.Code.IDEncr),
      keyEncr: Attributes.get(attrs, Attributes.Code.KeyEncr),
      level: IAccessStore.AccessLevel.Owner
    }));
  }

  ///
  function groupAddUser(GroupAddUserParams calldata p) external
  {
    signCheck(p.signer, p.signature);

    // Checking access rights
    IAccessStore.Access memory signerAccess = IAccessStore(accessStore).userAccess(usersStore[p.signer].IDHash, IAccessStore.AccessKind.UserGroup, p.groupIDHash);
    require(signerAccess.level == IAccessStore.AccessLevel.Owner || signerAccess.level == IAccessStore.AccessLevel.Admin, "DNY");

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
    IAccessStore(accessStore).setAccess(keccak256(abi.encode(p.userIDHash, IAccessStore.AccessKind.UserGroup)), IAccessStore.Access({
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
    IAccessStore.AccessLevel signerAccessLevel = IAccessStore(accessStore).userAccess(usersStore[signer].IDHash, IAccessStore.AccessKind.UserGroup, groupIDHash).level;
    require(signerAccessLevel == IAccessStore.AccessLevel.Owner || signerAccessLevel == IAccessStore.AccessLevel.Admin, "DNY");

    // Removing a user from a group
    for(uint i; i < userGroups[groupIDHash].members.length; i++) {
      if (userGroups[groupIDHash].members[i].userIDHash == userIDHash) {
          userGroups[groupIDHash].members[i] = userGroups[groupIDHash].members[userGroups[groupIDHash].members.length-1];
          userGroups[groupIDHash].members.pop();
      }
    }

    // Removing a group's access key
    require(IAccessStore(accessStore).setAccess(keccak256(abi.encode(userIDHash, IAccessStore.AccessKind.UserGroup)), IAccessStore.Access(bytes32(0), new bytes(0), new bytes(0), IAccessStore.AccessLevel.NoAccess)) == 1, "NFD");
  }

  function userGroupGetByID(bytes32 groupIdHash) external view returns(UserGroup memory) {
    return(userGroups[groupIdHash]);
  }
}

