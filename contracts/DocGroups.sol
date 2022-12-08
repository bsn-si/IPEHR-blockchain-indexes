// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./Users.sol";

contract DocGroups is Users {
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
        bytes32 accessID = keccak256(abi.encode(p.groupIdHash, AccessKind.DocGroup));
        require(accessStore[accessID].length == 0, "AEX");

        User memory owner = users[p.signer];
        require(owner.IDHash != bytes32(0), "NFD");

        // List of users who have access to the group
        setAccess(accessID, Access({
            idHash: keccak256(abi.encode(owner.IDHash)),
            idEncr: p.userIdEncr,
            keyEncr: new bytes(0),
            level: AccessLevel.Owner
        }));

        require(p.attrs.length > 0, "REQ");

        for (uint i; i < p.attrs.length; i++){
            docGroups[p.groupIdHash].params[p.attrs[i].code] = p.attrs[i].value;
        }

        // List of groups that the user has access to
        setAccess(keccak256((abi.encode(owner.IDHash, AccessKind.DocGroup))), Access({
            idHash: p.groupIdHash,
            idEncr: p.groupIdEncr,
            keyEncr: p.keyEncr,
            level: AccessLevel.Owner
        }));
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
        bytes32 userIDHash = users[signer].IDHash;
        require(userIDHash != bytes32(0), "NFD");

        // Checking access
        AccessLevel level = userAccess(
            keccak256(abi.encode(userIDHash, AccessKind.DocGroup)), 
            AccessKind.DocGroup, 
            groupIdHash
        ).level;
        require(level == AccessLevel.Owner || level == AccessLevel.Admin, "DND");

        // Checking the duplicate
        require(docGroups[groupIdHash].CIDHashes[CIDHash] == false, "AEX");

        docGroups[groupIdHash].CIDHashes[CIDHash] = true;
        docGroups[groupIdHash].CIDEncrs.push(CIDEncr);
  }

    function docGroupGetDocs(bytes32 groupIdHash) external view returns (bytes[] memory) {
        return docGroups[groupIdHash].CIDEncrs;
    }
}
