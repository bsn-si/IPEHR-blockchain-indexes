// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./Users.sol";

contract DocGroups is Users {
    struct DocumentGroup {
        mapping(bytes32 => bool)    CIDHashes;
        mapping(bytes32 => bytes)   params;
        bytes[]     CIDEncrs;   // CIDs encrypted with the group key 
        bytes32[]   userGroups;
    }

    mapping (bytes32 => DocumentGroup) docGroups;  // idHash => DocumentGroup

    struct DocGroupCreateParams {
        bytes32 groupIdHash;
        bytes  groupIdEncr;     // group id  encrypted with user pub key
        bytes  keyEncr;         // group key encrypted with user pub key
        bytes  userIdEncr;      // user id   encrypted with group key
        KeyValue[]  params;
        address signer;
        bytes   signature;
    }

    function docGroupCreate(
        DocGroupCreateParams calldata p
    ) 
        external
    {
        // Checking the duplicate
        bytes32 accessID = keccak256(abi.encode(p.groupIdHash, AccessKind.DocGroup));
        require(accessStore[accessID].length == 0, "AEX");

        User memory owner = users[p.signer];
        require(owner.id != bytes32(0), "NFD");

        // List of users who have access to the group
        accessStore[accessID].push(Object({
            idHash: keccak256(abi.encode(owner.id)),
            idEncr: p.userIdEncr,
            keyEncr: new bytes(0),
            level: AccessLevel.Owner
        }));

        require(p.params.length > 0, "REQ");

        for (uint i; i < p.params.length; i++){
            docGroups[p.groupIdHash].params[p.params[i].key] = p.params[i].value;
        }

        bytes32 payloadHash = keccak256(abi.encode("docGroupCreate", p.groupIdHash, p.groupIdEncr, p.keyEncr, p.userIdEncr, p.params));
        require(signCheck(payloadHash, p.signer, p.signature), "SIG");

        // List of groups that the user has access to
        accessID = keccak256((abi.encode(owner.id, AccessKind.DocGroup)));
        accessStore[accessID].push(Object({
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
        // Signature verification
        bytes32 payloadHash = keccak256(abi.encode("docGroupAddDoc", CIDEncr));
        require(signCheck(payloadHash, signer, signature), "SIG");

        // Checking user existence
        User storage user = users[signer];
        require(user.id != bytes32(0), "NFD");

        // Checking access
        AccessLevel level = getUserAccessLevel(
            keccak256(abi.encode(user.id, AccessKind.DocGroup)), 
            AccessKind.DocGroup, 
            groupIdHash
        );
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
