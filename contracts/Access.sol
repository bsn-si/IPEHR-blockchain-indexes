// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./Restrictable.sol";

contract Access is Restrictable {
    enum AccessLevel { NoAccess, Owner, Admin, Read }
    enum AccessKind { Doc, DocGroup, UserGroup }

    struct Object {
        bytes32      idHash;
        bytes        idEncr;
        bytes        keyEncr;
        AccessLevel  level;
    }

    mapping(bytes32 => Object[]) accessStore;     // idHash => Object[]

    function getAccessByIdHash(
        bytes32 userIdHash, 
        bytes32 objectIdHash
    ) 
        external view returns(Object memory) 
    {
        for (uint i; i < accessStore[userIdHash].length; i++){
            if (accessStore[userIdHash][i].idHash == objectIdHash) {
                return accessStore[userIdHash][i];
            }
        }

        revert("NFD");
    }

    function getUserAccessList(bytes32 userIdHash) external view returns (Object[] memory) {
        require(accessStore[userIdHash].length > 0, "NFD");
        return accessStore[userIdHash];
    }

    function getUserAccessLevel(
        bytes32 userID,
        AccessKind kind,
        bytes32 idHash
    )
        internal view returns (AccessLevel) 
    {
        bytes32 accessID = keccak256(abi.encode(userID, kind));
        for(uint i; i < accessStore[accessID].length; i++){
            if (accessStore[accessID][i].idHash == idHash) {
                return accessStore[accessID][i].level;
            }
        }

        // Checking groups
        accessID = keccak256(abi.encode(userID, AccessKind.UserGroup));
        for (uint i = 0; i < accessStore[accessID].length; i++) {
            for (uint j = 0; j < accessStore[accessID].length; j++) {
                if (accessStore[accessID][j].idHash == idHash) {
                    return accessStore[accessID][j].level;
                }
            }
        }

        return AccessLevel.NoAccess;
    }

}
