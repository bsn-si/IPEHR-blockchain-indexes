// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./interfaces/IAccessStore.sol";
import "./interfaces/IUsers.sol";
import "./Restrictable.sol";
import "./ImmutableState.sol";

contract AccessStore is IAccessStore, Restrictable {
    /**
    * accessID => Access[]
    * accessID is keccak256(objectID+AccessKind)
    */
    mapping(bytes32 => Access[]) accessStore;
    mapping(bytes32 => bool) private knownIDs;

    address public users;

    ///
    function setUsersContractAddress(address _users) external {
        require(users == address(0));
        users = _users;
    }

    ///
    function setAccess(
        bytes32 accessID,
        Access memory a,
        address signer,
        uint deadline,
        bytes calldata signature
    )
        external returns(AccessAction)
    {
        signCheck(signer, deadline, signature);

        bytes32 signerIDHash = IUsers(users).getUser(signer).IDHash;
        require(signerIDHash != bytes32(0), "NFD1");

        if (knownIDs[a.idHash]) {
            bytes32 signerAccessID = keccak256(abi.encode(signerIDHash, a.kind));
            Access memory signerAccess = getAccessByIdHash(signerAccessID, a.idHash);
            require(signerAccess.level == AccessLevel.Owner || signerAccess.level == AccessLevel.Admin, "DNY");
        }

        for (uint i; i < accessStore[accessID].length; i++) {
            if (accessStore[accessID][i].idHash == a.idHash) {
                accessStore[accessID][i].idEncr = a.idEncr;
                accessStore[accessID][i].keyEncr = a.keyEncr;
                accessStore[accessID][i].level = a.level;
                return AccessAction.Update;
            }
        }

        accessStore[accessID].push(a);
        knownIDs[a.idHash] = true;
        return AccessAction.Insert;
    }

    ///
    function getAccess(bytes32 accessID) external view returns(Access[] memory) {
        return accessStore[accessID];
    }

    ///
    function getAccessByIdHash(bytes32 accessID, bytes32 accessIdHash) public view returns(Access memory)
    {
        for (uint i; i < accessStore[accessID].length; i++){
            if (accessStore[accessID][i].idHash == accessIdHash) {
                return accessStore[accessID][i];
            }
        }

        revert("NFD");
    }

    ///
    function userAccess(bytes32 userIDHash, AccessKind kind, bytes32 idHash) external view returns (Access memory)
    {
        bytes32 accessID = keccak256(abi.encode(userIDHash, kind));
        for(uint i; i < accessStore[accessID].length; i++){
            if (accessStore[accessID][i].idHash == idHash) {
                return accessStore[accessID][i];
            }
        }

        // Checking groups
        bytes32 accessIDGroup = keccak256(abi.encode(userIDHash, AccessKind.UserGroup));
        for (uint i = 0; i < accessStore[accessIDGroup].length; i++) {
            if (accessStore[accessIDGroup][i].idHash == idHash) {
                return accessStore[accessIDGroup][i];
            }
        }

        return Access(AccessKind.NoKind, bytes32(0), new bytes(0), new bytes(0), AccessLevel.NoAccess);
    }
}
