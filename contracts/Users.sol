// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./libraries/Attributes.sol";
import "./Access.sol";

contract Users is AccessStore {
    enum Role { Patient, Doctor }

    struct User {
      bytes32   id;
      bytes32   systemID;
      Role      role;
      bytes     pwdHash;
    }

    struct GroupMember {
      bytes32 userIDHash;
      bytes userIDEncr;    // userIDs encrypted by group key
    }

    struct UserGroup {
      Attributes.Attribute[] attrs;
      GroupMember[] members;  
    }

  mapping (address => User) public users;
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
    require(userGroups[p.groupIdHash].attrs.length == 0, "AEX");

    // Creating a group
    for (uint i; i < p.attrs.length; i++) {
      userGroups[p.groupIdHash].attrs.push(p.attrs[i]);
    }

    // Adding a groupID to a user's group list
    setAccess(keccak256(abi.encode(users[p.signer].id, AccessKind.UserGroup)), Access({
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
    bytes addingUserIDEncr; // userID encrypted by group key
    bytes keyEncr;          // group key encrypted by adding user public key
    address signer;
    bytes signature;
  }

  ///
  function groupAddUser(GroupAddUserParams calldata p) external
  {
    signCheck(p.signer, p.signature);

    // Checking user existence
    bytes32 addingUserID = users[p.addingUserAddr].id;
    require(addingUserID != bytes32(0), "NFD");

    // Checking access rights
    Access memory signerAccess = userAccess(users[p.signer].id, AccessKind.UserGroup, p.groupIdHash);
    require(signerAccess.level == AccessLevel.Owner || signerAccess.level == AccessLevel.Admin, "DNY");
    
    // Checking user not in group already
    require(userAccess(addingUserID, AccessKind.UserGroup, p.groupIdHash).level == AccessLevel.NoAccess, "AEX");

    // Adding a user to a group
    userGroups[p.groupIdHash].members.push(GroupMember({
      userIDHash: keccak256(abi.encode(addingUserID)),
      userIDEncr: p.addingUserIDEncr
    }));

    // Adding the group's secret key
    setAccess(keccak256(abi.encode(addingUserID, AccessKind.UserGroup)), Access({
      idHash: p.groupIdHash,
      idEncr: signerAccess.idEncr,
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
    Access memory signerAccess = userAccess(users[signer].id, AccessKind.UserGroup, groupIdHash);
    require(signerAccess.level == AccessLevel.Owner || signerAccess.level == AccessLevel.Admin, "DNY");

    // Removing a user from a group
    bytes32 removingUserIDHash = keccak256(abi.encode(users[removingUserAddr].id));
    for(uint i; i < userGroups[groupIdHash].members.length; i++) {
      if (userGroups[groupIdHash].members[i].userIDHash == removingUserIDHash) {
          userGroups[groupIdHash].members[i] = userGroups[groupIdHash].members[userGroups[groupIdHash].members.length-1];
          userGroups[groupIdHash].members.pop();
      }
    }

    // Removing a group's access key
    bytes32 accessID = keccak256(abi.encode(users[removingUserAddr].id, AccessKind.UserGroup));
    require(setAccess(accessID, ZeroAccess) == 1,"NFD");
  }

  function userGroupGetByID(bytes32 groupIdHash) external view returns(UserGroup memory) {
    return(userGroups[groupIdHash]);
  }
}

