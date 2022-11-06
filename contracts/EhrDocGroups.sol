// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.4;

import "./EhrAccess.sol";
import "./EhrUsers.sol";

contract EhrDocGroups is EhrAccess, EhrUsers {
  struct DocumentGroup {
    bytes32   owner;
    bytes     description;
    bytes[]   docs;         // array CIDs
    bytes32[] userGroups;   // array userGroupIDs
  }

  mapping (bytes32 => DocumentGroup) docGroups;  // ID => DocumentGroup

  function docGroupCreate(
    bytes32 groupID,
    bytes32 owner,
    bytes calldata description,
    bytes calldata keyEncrypted,
    uint nonce,
    address signer,
    bytes calldata signature
  ) external checkNonce(signer, nonce) {
      require(docGroups[groupID].owner == bytes32(0), "AEX");
      bytes32 payloadHash = keccak256(abi.encode("docGroupCreate", groupID, owner, description, keyEncrypted, nonce));
      require(SignChecker.signCheck(payloadHash, signer, signature), "SIG");
      bytes32 accessKey = keccak256((abi.encode(owner, groupID)));
      accessStore[accessKey] = Access({
        level: AccessLevel.Owner,
        keyEncrypted: keyEncrypted
      });
  }

  function docGroupAddDoc(
    bytes32 groupID,
    bytes calldata CID,
    uint nonce,
    address signer,
    bytes calldata signature) external checkNonce(signer, nonce) {
      bytes32 payloadHash = keccak256(abi.encode("docGroupAddDoc", CID, nonce));
      require(SignChecker.signCheck(payloadHash, signer, signature), "SIG");
      User storage user = users[signer];
      require(user.id != bytes32(0), "NFD");
      bytes32 accessKey = keccak256((abi.encode(user.id, groupID)));
      Access storage access = accessStore[accessKey];
      require(access.keyEncrypted.length > 0 && (access.level == AccessLevel.Owner || access.level == AccessLevel.Admin), "DND");
      docGroups[groupID].docs.push(CID);
  }

  function docGroupGetDocs(
    bytes32 groupID,
    uint nonce,
    address signer,
    bytes calldata signature
  ) external checkNonce(signer, nonce) returns (bytes[] memory) {
    bytes32 payloadHash = keccak256(abi.encode("docGroupGetDocs", groupID, nonce));
    require(SignChecker.signCheck(payloadHash, signer, signature), "SIG");
    User storage user = users[signer];
    require(user.id != bytes32(0), "NFD");
    bytes32 accessKey = keccak256((abi.encode(user.id, groupID)));
    Access storage access = accessStore[accessKey];
    require(access.keyEncrypted.length > 0 && (access.level == AccessLevel.Owner || access.level == AccessLevel.Admin || access.level == AccessLevel.Read), "DND");
    return docGroups[groupID].docs;
  }
}