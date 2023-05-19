// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./interfaces/IAccessStore.sol";

contract AccessStore is IAccessStore {
    /**
    * accessID => Access[]
    * accessID is keccak256(objectID+AccessKind)
    */
    mapping(bytes32 => Access[]) accessStore;

    ///
    function setAccess(
        bytes32 accessID,
        Access memory o
    ) 
        external returns(uint8)
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
    function getAccess(bytes32 accessID) external view returns(Access[] memory) {
        return accessStore[accessID];
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
    function userAccess(bytes32 userID, AccessKind kind, bytes32 idHash) external view returns (Access memory) 
    {
        bytes32 accessID = keccak256(abi.encode(userID, kind));
        for(uint i; i < accessStore[accessID].length; i++){
            if (accessStore[accessID][i].idHash == idHash) {
                return accessStore[accessID][i];
            }
        }

        // Checking groups
        bytes32 accessIDGroup = keccak256(abi.encode(userID, AccessKind.UserGroup));
        for (uint i = 0; i < accessStore[accessIDGroup].length; i++) {
            if (accessStore[accessIDGroup][i].idHash == idHash) {
                return accessStore[accessIDGroup][i];
            }
        }

        return Access(bytes32(0), new bytes(0), new bytes(0), AccessLevel.NoAccess);
    }
}
