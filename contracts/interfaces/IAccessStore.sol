// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

interface IAccessStore {
    enum AccessLevel { NoAccess, Owner, Admin, Read }
    enum AccessKind { Doc, DocGroup, UserGroup }
    enum AccessAction { NoAction, Update, Insert }
    
    struct Access {
        bytes32      idHash;
        bytes        idEncr;    // id encrypted by access key
        bytes        keyEncr;   // access key encrypted by user private key
        AccessLevel  level;
    }

    function getAccess(bytes32 accessID) external view returns(Access[] memory);
    function setAccess(bytes32 accessID, Access memory o) external returns(uint8);
    function getAccessByIdHash(bytes32 accessID, bytes32 accessIdHash) external view returns(Access memory);
    function userAccess(bytes32 userID, AccessKind kind, bytes32 idHash) external view returns (Access memory);
}
