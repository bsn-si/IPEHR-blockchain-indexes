// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./interfaces/IUsers.sol";
import "./Docs.sol";

abstract contract DocGroups is Docs {
    struct DocumentGroup {
        mapping(bytes32 => bool) CIDHashes;
        mapping(Attributes.Code => bytes)   params;
        bytes[]     CIDEncrs;   // CIDs encrypted with the group key 
        bytes32[]   userGroups;
    }

    mapping (bytes32 => DocumentGroup) docGroups;  // idHash => DocumentGroup

    struct DocGroupCreateParams {
        bytes32     groupIdHash;
        bytes       groupIdEncr;     // group id  encrypted with user pub key
        bytes       keyEncr;         // group key encrypted with user pub key
        bytes       userIdEncr;      // user id   encrypted with group key
        Attributes.Attribute[] attrs;
        address     signer;
        bytes       signature;
    }

    function docGroupCreate(DocGroupCreateParams calldata p) 
        external 
    {
        signCheck(p.signer, p.signature);

        // Checking the duplicate
        bytes32 accessID = keccak256(abi.encode(p.groupIdHash, IAccessStore.AccessKind.DocGroup));
        require(IAccessStore(accessStore).getAccess(accessID).length == 0, "AEX");

        bytes32 ownerIDHash = IUsers(users).getUser(p.signer).IDHash;
        require(ownerIDHash != bytes32(0), "NFD");

        // List of users who have access to the group
        IAccessStore(accessStore).setAccess(accessID, IAccessStore.Access({
            idHash: keccak256(abi.encode(ownerIDHash)),
            idEncr: p.userIdEncr,
            keyEncr: new bytes(0),
            level: IAccessStore.AccessLevel.Owner
        }));

        require(p.attrs.length > 0, "REQ");

        for (uint i; i < p.attrs.length; i++){
            docGroups[p.groupIdHash].params[p.attrs[i].code] = p.attrs[i].value;
        }

        // List of groups that the user has access to
        IAccessStore(accessStore).setAccess(
            keccak256((abi.encode(ownerIDHash, IAccessStore.AccessKind.DocGroup))), 
            IAccessStore.Access({
                idHash: p.groupIdHash,
                idEncr: p.groupIdEncr,
                keyEncr: p.keyEncr,
                level: IAccessStore.AccessLevel.Owner
            })
        );
    }

    function docGroupAddDoc(
        bytes32 groupIdHash,
        bytes32 CIDHash,
        bytes calldata CIDEncr,
        address signer,
        bytes calldata signature
    ) 
        external 
    {
        signCheck(signer, signature);

        // Checking user existence
        bytes32 userIDHash = IUsers(users).getUser(signer).IDHash;
        require(userIDHash != bytes32(0), "NFD");

        // Checking access
        IAccessStore.AccessLevel level = IAccessStore(accessStore).userAccess(
            keccak256(abi.encode(userIDHash, IAccessStore.AccessKind.DocGroup)), 
            IAccessStore.AccessKind.DocGroup, 
            groupIdHash
        ).level;
        require(level == IAccessStore.AccessLevel.Owner || level == IAccessStore.AccessLevel.Admin, "DND");

        // Checking the duplicate
        require(docGroups[groupIdHash].CIDHashes[CIDHash] == false, "AEX");

        docGroups[groupIdHash].CIDHashes[CIDHash] = true;
        docGroups[groupIdHash].CIDEncrs.push(CIDEncr);
  }

    function docGroupGetDocs(bytes32 groupIdHash) external view returns (bytes[] memory) {
        return docGroups[groupIdHash].CIDEncrs;
    }
}
