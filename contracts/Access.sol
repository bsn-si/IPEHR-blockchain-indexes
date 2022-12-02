// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./Restrictable.sol";

contract AccessStore is Restrictable {
    enum AccessLevel { NoAccess, Owner, Admin, Read }
    enum AccessKind { Doc, DocGroup, UserGroup }

    struct Access {
        bytes32      idHash;
        bytes        idEncr;    // id encrypted by access key
        bytes        keyEncr;   // access key encrypted by user private key
        AccessLevel  level;
    }

    Access ZeroAccess = Access({
        idHash: bytes32(0),
        idEncr: new bytes(0),
        keyEncr: new bytes(0),
        level: AccessLevel.NoAccess
    });

    mapping(bytes32 => Access[]) private accessStore;     // accessID => Access[]

    ///
    // Returns 1 on update or 2 on insert
    function setAccess(bytes32 accessID, Access memory o) internal returns(uint8)
    {
        for(uint i; i < accessStore[accessID].length; i++) {
            if (accessStore[accessID][i].idHash == o.idHash) {
                accessStore[accessID][i].idEncr = o.idEncr;
                accessStore[accessID][i].keyEncr = o.keyEncr;
                accessStore[accessID][i].level = o.level;
                return 1;
            }
        }

        accessStore[accessID].push(o);
        return 2;
    }

    ///
    function getAccessByIdHash(bytes32 accessID, bytes32 accessIdHash) external view returns(Access memory) 
    {
        for (uint i; i < accessStore[accessID].length; i++){
            if (accessStore[accessID][i].idHash == accessIdHash) {
                return accessStore[accessID][i];
            }
        }

        revert("NFD");
    }

    ///
    function getUserAccessList(bytes32 accessID) public view returns (Access[] memory) 
    {
        return accessStore[accessID];
    }

    ///
    function userAccess(bytes32 userID, AccessKind kind, bytes32 idHash) public view returns (Access memory) 
    {
        bytes32 accessID = keccak256(abi.encode(userID, kind));
        for(uint i; i < accessStore[accessID].length; i++){
            if (accessStore[accessID][i].idHash == idHash) {
                return accessStore[accessID][i];
            }
        }

        // Checking groups
        accessID = keccak256(abi.encode(userID, AccessKind.UserGroup));
        for (uint i = 0; i < accessStore[accessID].length; i++) {
            for (uint j = 0; j < accessStore[accessID].length; j++) {
                if (accessStore[accessID][j].idHash == idHash) {
                    return accessStore[accessID][j];
                }
            }
        }

        return ZeroAccess;
    }
}
