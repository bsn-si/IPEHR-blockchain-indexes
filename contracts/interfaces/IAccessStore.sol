// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

interface IAccessStore {
    enum AccessLevel { NoAccess, Owner, Admin, Read }
    enum AccessKind { NoKind, Doc, DocGroup, UserGroup }
    enum AccessAction { NoAction, Update, Insert }

    struct Access {
        AccessKind   kind;
        bytes32      idHash;
        bytes        idEncr;    // id encrypted by access key
        bytes        keyEncr;   // access key encrypted by user private key
        AccessLevel  level;
    }

    function setUsersContractAddress(address _users) external;
    function getAccess(bytes32 accessID) external view returns(Access[] memory);
    function setAccess(bytes32 accessID, Access memory o, address signer, uint deadline, bytes calldata signature) external returns(AccessAction);
    function getAccessByIdHash(bytes32 accessID, bytes32 accessIdHash) external view returns(Access memory);
    function userAccess(bytes32 userID, AccessKind kind, bytes32 idHash) external view returns (Access memory);
}
