// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./interfaces/IUsers.sol";
import "./Docs.sol";

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
        //bytes       userIDEncr;      // user id   encrypted with group key
        Attributes.Attribute[] attrs;
            // group id  encrypted with user pub key
            // group key encrypted with user pub key
        address     signer;
        uint        deadline;
        bytes       signature;
    }

    function docGroupCreate(DocGroupCreateParams calldata p) 
        external 
    {
        signCheck(p.signer, p.deadline, p.signature);

        // Checking the duplicate        
        require(Attributes.get(docGroups[p.groupIDHash].attrs, Attributes.Code.NameEncr).length == 0, "AEX");

        bytes32 ownerIDHash = IUsers(users).getUser(p.signer).IDHash;
        require(ownerIDHash != bytes32(0), "NFD");
        require(p.attrs.length > 0, "REQ");

        for (uint i; i < p.attrs.length; i++) {
            docGroups[p.groupIDHash].attrs.push(p.attrs[i]);
        }
    }

    function docGroupAddDoc(
        bytes32 groupIDHash,
        bytes32 docCIDHash,
        bytes calldata docCIDEncr,
        address signer,
        uint deadline,
        bytes calldata signature
    ) 
        external 
    {
        signCheck(signer, deadline, signature);

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
