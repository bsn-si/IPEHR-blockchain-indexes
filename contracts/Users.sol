// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./libraries/Attributes.sol";

import "./interfaces/IAccessStore.sol";
import "./interfaces/IUsers.sol";

import "@openzeppelin/contracts/utils/Multicall.sol";
import "./Restrictable.sol";
import "./ImmutableState.sol";

contract Users is IUsers, ImmutableState, Restrictable, Multicall {
  mapping (address => User) usersStore;
  mapping (bytes32 => UserGroup) userGroups;    // groupIdHash => UserGroup
  mapping (uint64 => address) userCodes;

  constructor(address _accessStore) ImmutableState(_accessStore, address(this), address(uint160(0))) {
    IAccessStore(accessStore).setUsersContractAddress(address(this));
  }

  ///
  function userNew(
    address addr, 
    bytes32 IDHash,        // sha3(userID+systemID) 
    Role role, 
    Attributes.Attribute[] calldata attrs,
    address signer,
    uint deadline,
    bytes calldata signature
  ) 
    external onlyAllowed(msg.sender) 
  {
    signCheck(signer, deadline, signature);

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

    if (role == Role.Doctor) {
      uint64 code = uint64(bytes8(IDHash)) % 99999999;
      require(userCodes[code] == address(0), "AEX");
      userCodes[code] = addr;
    }
  }

  ///
  function getUser(address addr) external view returns(User memory) {
    return usersStore[addr];
  }

  ///
  function getUserByCode(uint64 code) external view returns(User memory) {
    return usersStore[userCodes[code]];
  }

  ///
  function userGroupCreate(
    bytes32 groupIdHash, 
    Attributes.Attribute[] calldata attrs, 
    address signer,
    uint deadline,
    bytes calldata signature
  ) 
      external onlyAllowed(msg.sender) 
  {
    signCheck(signer, deadline, signature);

    // Checking user existence
    require(usersStore[signer].IDHash != bytes32(0), "NFD");

    // Checking group absence
    require(userGroups[groupIdHash].attrs.length == 0, "AEX");

    // Creating a group
    for (uint i; i < attrs.length; i++) {
      userGroups[groupIdHash].attrs.push(attrs[i]);
    }
  }

  ///
  function groupAddUser(GroupAddUserParams calldata p) external
  {
    signCheck(p.signer, p.deadline, p.signature);

    // Checking access rights
    IAccessStore.Access memory signerAccess = IAccessStore(accessStore).userAccess(usersStore[p.signer].IDHash, IAccessStore.AccessKind.UserGroup, p.groupIDHash);
    require(signerAccess.level == IAccessStore.AccessLevel.Owner || signerAccess.level == IAccessStore.AccessLevel.Admin, "DNY");

    // Checking group is exist
    require(userGroups[p.groupIDHash].attrs.length > 0, "NFD");

    // Checking that user not in the group
    for (uint i; i < userGroups[p.groupIDHash].members.length; i++) {
      if (userGroups[p.groupIDHash].members[i].userIDHash == p.userIDHash) revert("AEX");
    }

    // Adding a user to a group
    userGroups[p.groupIDHash].members.push(GroupMember({
      userIDHash: p.userIDHash,
      userIDEncr: p.userIDEncr
    }));
  }

  ///
  function groupRemoveUser(
      bytes32 groupIDHash, 
      bytes32 userIDHash, 
      address signer,
      uint deadline,
      bytes calldata signature
  ) 
      external
  {
    signCheck(signer, deadline, signature);

    // Checking access rights
    IAccessStore.AccessLevel signerAccessLevel = IAccessStore(accessStore).userAccess(usersStore[signer].IDHash, IAccessStore.AccessKind.UserGroup, groupIDHash).level;
    require(signerAccessLevel == IAccessStore.AccessLevel.Owner || signerAccessLevel == IAccessStore.AccessLevel.Admin, "DNY");

    // Removing the user from the group
    for(uint i; i < userGroups[groupIDHash].members.length; i++) {
      if (userGroups[groupIDHash].members[i].userIDHash == userIDHash) {
          userGroups[groupIDHash].members[i] = userGroups[groupIDHash].members[userGroups[groupIDHash].members.length-1];
          userGroups[groupIDHash].members.pop();
      }
    }

    // Removing a group's access key
    // moved to the backend

  }

  ///
  function userGroupGetByID(bytes32 groupIdHash) external view returns(UserGroup memory) {
    return(userGroups[groupIdHash]);
  }

  ///
  function setAccess(
    bytes32 accessID,
    IAccessStore.Access memory a,
    address signer,
    uint deadline,
    bytes calldata signature
  )
    external
  {
    IAccessStore(accessStore).setAccess(accessID, a, signer, deadline, signature);
  }
}
