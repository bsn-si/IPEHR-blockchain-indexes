// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./interfaces/IUsers.sol";
import "./Docs.sol";
import "hardhat/console.sol";

abstract contract DocGroups is Docs {
    struct DocumentGroup {
        mapping(bytes32 => bool)          CIDHashes;
        Attributes.Attribute[]            attrs;
        bytes[]                           CIDEncrs;   // CIDs encrypted with the group key 
        bytes32[]                         userGroups; // userGroups that have access to this group
    }

    mapping (bytes32 => DocumentGroup) docGroups;  // idHash => DocumentGroup

    struct DocGroupCreateParams {
        bytes32     groupIDHash;       
        Attributes.Attribute[] attrs;
            // Expected attributes:
            // group id   encrypted with group key
            // group key  encrypted with group key
            // group name encrypted with group key
        
        address     signer;
        bytes       signature;
    }

    function docGroupCreate(DocGroupCreateParams calldata p) 
        external 
    {
        signCheck(p.signer, p.signature);

        require(p.attrs.length >= 3, "REQ");

        // Checking the duplicate        
        require(Attributes.get(docGroups[p.groupIDHash].attrs, Attributes.Code.NameEncr).length == 0, "AEX");

        bytes32 ownerIDHash = IUsers(users).getUser(p.signer).IDHash;
        require(ownerIDHash != bytes32(0), "NFD");

        for (uint i; i < p.attrs.length; i++) {
            docGroups[p.groupIDHash].attrs.push(p.attrs[i]);
        }

        /*
        IAccessStore(accessStore).setAccess(
            keccak256((abi.encode(ownerIDHash, IAccessStore.AccessKind.DocGroup))), 
            IAccessStore.Access({
                idHash: p.groupIDHash,
                idEncr: Attributes.get(p.attrs, Attributes.Code.IDEncr),
                keyEncr: Attributes.get(p.attrs, Attributes.Code.KeyEncr),
                level: IAccessStore.AccessLevel.Owner
            })
        );
        */
    }

    function docGroupAddDoc(
        bytes32 groupIDHash,
        bytes32 docCIDHash,
        bytes calldata docCIDEncr,
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
            userIDHash, 
            IAccessStore.AccessKind.DocGroup, 
            groupIDHash
        ).level;

        require(level == IAccessStore.AccessLevel.Owner || level == IAccessStore.AccessLevel.Admin, "DNY");

        // Checking the duplicate
        require(docGroups[groupIDHash].CIDHashes[docCIDHash] == false, "AEX");

        docGroups[groupIDHash].CIDHashes[docCIDHash] = true;
        docGroups[groupIDHash].CIDEncrs.push(docCIDEncr);
    }

    function docGroupGetDocs(bytes32 groupIdHash) external view returns (bytes[] memory) {
        return docGroups[groupIdHash].CIDEncrs;
    }

    function docGroupGetAttrs(bytes32 groupIdHash) external view returns (Attributes.Attribute[] memory) {
        return docGroups[groupIdHash].attrs;
    }
}
