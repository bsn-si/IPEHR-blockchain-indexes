// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Multicall.sol";
import "./Users.sol";
import "./Access.sol";
import "./EhrDocs.sol";
import "./Restrictable.sol";

contract EhrIndexer is Ownable, Multicall, Restrictable, Users, EhrDocs {
    /**
      Error codes:
    ADL - already deleted
    WTP - wrong type passed
    LST - new version of the EHR document must be the latest
    NFD - not found
    AEX - already exists
    DND - access denied
    TMT - timeout
    NNC - wrong nonce
    SIG - invalid signature
  */

  struct DataEntry {
    uint128 groupID;
    mapping (string => bytes) valueSet;
    bytes docStorIDEncr;
  }

  struct Element {
    bytes32 itemType;
    bytes32 elementType;
    bytes32 nodeID;
    bytes32 name;
    DataEntry[] dataEntries;
  }

  struct Node {
    bytes32 nodeType;
    bytes32 nodeID;
    mapping (bytes32 => Node) next;
    mapping (bytes32 => Element) items;
  }

  Node public dataSearch;
}
