// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Multicall.sol";
import "./EhrUsers.sol";
import "./EhrAccess.sol";
import "./EhrDocs.sol";
import "./EhrRestrictable.sol";

contract EhrIndexer is Ownable, Multicall, EhrRestrictable, EhrUsers, EhrDocs {
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
  

    function setGroupAccess(
        bytes32 accessID, 
        Access calldata access,
        uint nonce,
        address signer, 
        bytes calldata signature
    ) 
        external checkNonce(signer, nonce) 
    {

        // Checking user existence
        require(users[signer].id != bytes32(0), "NFD");

        // Signature verification
        bytes32 payloadHash = keccak256(abi.encode("setGroupAccess", accessID, access, nonce));
        require(SignChecker.signCheck(payloadHash, signer, signature), "SIG");

        accessStore[accessID] = access;
    }

}
