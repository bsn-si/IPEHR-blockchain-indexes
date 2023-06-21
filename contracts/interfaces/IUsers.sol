// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "../libraries/Attributes.sol";
import "./IAccessStore.sol";

interface IUsers {
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
    
    function userNew(
        address addr, 
        bytes32 IDHash,        // sha3(userID+systemID) 
        Role role, 
        Attributes.Attribute[] calldata attrs,
        address signer,
        uint deadline,
        bytes calldata signature
    ) external;

    function getUser(address addr) external view returns(User memory);

    struct UserGroup {
      Attributes.Attribute[] attrs;
      GroupMember[] members;  
    }

    function userGroupCreate(
        bytes32 groupIdHash, 
        Attributes.Attribute[] calldata attrs, 
        address signer,
        uint deadline,
        bytes calldata signature
    ) external;

    struct GroupAddUserParams {
        bytes32 groupIDHash;
        bytes32 userIDHash;
        IAccessStore.AccessLevel level;
        bytes userIDEncr;       // userID encrypted by group key
        bytes keyEncr;          // group key encrypted by adding user public key
        address signer;
        uint deadline;
        bytes signature;
    }

    function groupAddUser(GroupAddUserParams calldata p) external;

    function groupRemoveUser(
      bytes32 groupIDHash, 
      bytes32 userIDHash, 
      address signer,
      uint deadline,
      bytes calldata signature
    ) external;

    function userGroupGetByID(bytes32 groupIdHash) external view returns(UserGroup memory);
}
