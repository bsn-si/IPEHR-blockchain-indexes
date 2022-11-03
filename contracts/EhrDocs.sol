// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.4;

import "./EhrAccess.sol";
import "./EhrUsers.sol";

contract EhrDocs is EhrAccess, EhrUsers {

    enum DocType { Ehr, EhrAccess, EhrStatus , Composition }
    enum DocStatus { Active, Deleted }

    struct DocumentMeta {
        DocType docType;
        DocStatus status;
        bytes   CID;
        bytes   dealCID;
        bytes   minerAddress;
        bytes   docUIDEncrypted;
        bytes32 docBaseUIDHash;
        bytes32 version;
        bool    isLast;
        uint32  timestamp;
    }

    mapping (bytes32  => mapping(DocType => DocumentMeta[])) ehrDocs; // ehr_id -> docType -> DocumentMeta[]
    mapping (bytes32  => bytes32) public ehrSubject;  // subjectKey -> ehr_id
    mapping (bytes32 => bool) cids;

    ///
    function setEhrSubject(
        bytes32 subjectKey, 
        bytes32 ehrId,
        uint nonce, 
        address signer, 
        bytes calldata signature
    ) 
        external onlyAllowed(msg.sender) checkNonce(signer, nonce)
    {
        // Signature verification
        bytes32 payloadHash = keccak256(abi.encode("setEhrSubject", subjectKey, ehrId, nonce));
        require(SignChecker.signCheck(payloadHash, signer, signature), "SIG");

        ehrSubject[subjectKey] = ehrId;
    }
    
    ///
    function addEhrDoc(
        bytes32 ehrId, 
        DocumentMeta calldata docMeta,
        bytes calldata keyEncrypted,
        uint nonce, 
        address signer, 
        bytes calldata signature
    ) 
        external onlyAllowed(msg.sender) checkNonce(signer, nonce)
    {
        // Signature verification
        bytes32 payloadHash = keccak256(abi.encode("addEhrDoc", ehrId, docMeta, keyEncrypted, nonce));
        require(SignChecker.signCheck(payloadHash, signer, signature), "SIG");
        
        require(cids[keccak256(abi.encode(docMeta.CID))] == false, "AEX");
        require(docMeta.isLast == true, "LST");
        require(users[signer].id != bytes32(0), "NFD");

        uint i;
        if (docMeta.docType == DocType.Ehr || docMeta.docType == DocType.EhrStatus) {
            for (i = 0; i < ehrDocs[ehrId][docMeta.docType].length; i++) {
                ehrDocs[ehrId][docMeta.docType][i].isLast = false;
            }
        }

        if (docMeta.docType == DocType.Composition) {
            for (i = 0; i < ehrDocs[ehrId][DocType.Composition].length; i++) {
                if (ehrDocs[ehrId][DocType.Composition][i].docBaseUIDHash == docMeta.docBaseUIDHash) {
                    ehrDocs[ehrId][DocType.Composition][i].isLast = false;
                }
            }
        }

        ehrDocs[ehrId][docMeta.docType].push(docMeta);

        cids[keccak256(abi.encode(docMeta.CID))] = true;

        bytes32 accessID = keccak256(abi.encode(users[signer].id, docMeta.CID));

        accessStore[accessID] = Access({
            level: AccessLevel.Admin,
            keyEncrypted: keyEncrypted
        });
    }

    ///
    function getEhrDocs(bytes32 ehrId, DocType docType) public view returns(DocumentMeta[] memory) {
        return ehrDocs[ehrId][docType];
    }

    ///
    function getLastEhrDocByType(bytes32 ehrId, DocType docType) public view returns(DocumentMeta memory) {
        for (uint i = 0; i < ehrDocs[ehrId][docType].length; i++) {
            if (ehrDocs[ehrId][docType][i].isLast == true) {
                return ehrDocs[ehrId][docType][i];
            }
        }
        revert("NFD");
    }

    ///
    function getDocByVersion(
        bytes32 ehrId,
        DocType docType,
        bytes32 docBaseUIDHash,
        bytes32 version
    )
        public view returns (DocumentMeta memory) 
    {
        for (uint i = 0; i < ehrDocs[ehrId][docType].length; i++) {
            if (ehrDocs[ehrId][docType][i].docBaseUIDHash == docBaseUIDHash && ehrDocs[ehrId][docType][i].version == version) {
                return ehrDocs[ehrId][docType][i];
            }
        }
        revert("NFD");
    }

    ///
    function getDocByTime(bytes32 ehrID, DocType docType, uint32 timestamp) 
        public view returns (DocumentMeta memory) 
    {
        DocumentMeta memory docMeta;
        for (uint i = 0; i < ehrDocs[ehrID][docType].length; i++) {
            if (ehrDocs[ehrID][docType][i].timestamp <= timestamp) {
                docMeta = ehrDocs[ehrID][docType][i];
            } else {
                break;
            }
        }

        require(docMeta.timestamp != 0, "NFD");

        return docMeta;
    }

    ///
    function getDocLastByBaseID(bytes32 ehrId, DocType docType, bytes32 docBaseUIDHash) 
        public view returns (DocumentMeta memory) 
    {
        for (uint i = 0; i < ehrDocs[ehrId][docType].length; i++) {
            if (ehrDocs[ehrId][docType][i].docBaseUIDHash == docBaseUIDHash) {
                return ehrDocs[ehrId][docType][i];
            }
        }
        revert("NFD");
    }

    ///
    function setDocAccess(
        bytes32         accessID,
        bytes  calldata CID,
        Access calldata access,
        uint            nonce,
        address         signer,
        bytes calldata  signature
    ) 
        external checkNonce(signer, nonce) 
    {    
        // Signature verification
        bytes32 payloadHash = keccak256(abi.encode("setDocAccess", accessID, CID, access, nonce));
        require(SignChecker.signCheck(payloadHash, signer, signature), "SIG");

        // Checking access rights
        {
            // Signer should be Owner or Admin of doc
            User memory user = users[signer];
            require(user.id != bytes32(0), "NFD");

            AccessLevel signerLevel = accessStore[keccak256(abi.encode(user.id, CID))].level;
            if (signerLevel == AccessLevel.NoAccess) {
                for (uint i = 0; i < user.groups.length; i++) {
                    signerLevel = accessStore[keccak256(abi.encode(user.groups[i], CID))].level;
                    if (signerLevel != AccessLevel.NoAccess) {
                        break;
                    }
                }
            }
            require(signerLevel == AccessLevel.Owner || signerLevel == AccessLevel.Admin, "DND");
            require(signerLevel == AccessLevel.Admin && accessStore[accessID].level != AccessLevel.Owner, "DND");
        }
        
        // Request validation
        if (access.level == AccessLevel.NoAccess) {
            require(access.keyEncrypted.length == 0);
        }

        // Set access
        accessStore[accessID] = access;
    }

    ///
    function deleteDoc(
        bytes32 ehrId, 
        DocType docType, 
        bytes32 docBaseUIDHash, 
        bytes32 version
    ) 
        external onlyAllowed(msg.sender) 
    {
        require(docType == DocType.Composition, "WTP");
        
        for (uint i = 0; i < ehrDocs[ehrId][docType].length; i++) {
            if (ehrDocs[ehrId][docType][i].docBaseUIDHash == docBaseUIDHash && ehrDocs[ehrId][docType][i].version == version) {
                require (ehrDocs[ehrId][docType][i].status != DocStatus.Deleted, "ADL");
                ehrDocs[ehrId][docType][i].status = DocStatus.Deleted;
                return;
            }
        }
        revert("NFD");
    }
}
