// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./Access.sol";
import "./Users.sol";

contract EhrDocs is Access, Users {

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

    struct AddEhrDocParams {
        bytes32 ehrId;
        DocumentMeta docMeta;
        bytes keyEncr;
        bytes CIDEncr;
        uint nonce;
        address signer; 
        bytes signature;
    }
    
    ///
    function addEhrDoc(
        AddEhrDocParams calldata p
    ) 
        external onlyAllowed(msg.sender) checkNonce(p.signer, p.nonce)
    {
        // Signature verification
        bytes32 payloadHash = keccak256(abi.encode("addEhrDoc", p.ehrId, p.docMeta, p.keyEncr, p.CIDEncr, p.nonce));
        require(SignChecker.signCheck(payloadHash, p.signer, p.signature), "SIG");

        bytes32 CIDHash = keccak256(abi.encode(p.docMeta.CID));
        require(cids[CIDHash] == false, "AEX");
        cids[CIDHash] = true;

        require(p.docMeta.isLast == true, "LST");
        require(users[p.signer].id != bytes32(0), "NFD");

        if (p.docMeta.docType == DocType.Ehr || p.docMeta.docType == DocType.EhrStatus) {
            for (uint i = 0; i < ehrDocs[p.ehrId][p.docMeta.docType].length; i++) {
                ehrDocs[p.ehrId][p.docMeta.docType][i].isLast = false;
            }
        }

        if (p.docMeta.docType == DocType.Composition) {
            for (uint i = 0; i < ehrDocs[p.ehrId][DocType.Composition].length; i++) {
                if (ehrDocs[p.ehrId][DocType.Composition][i].docBaseUIDHash == p.docMeta.docBaseUIDHash) {
                    ehrDocs[p.ehrId][DocType.Composition][i].isLast = false;
                }
            }
        }

        ehrDocs[p.ehrId][p.docMeta.docType].push(p.docMeta);

        bytes32 accessID = keccak256(abi.encode(users[p.signer].id, AccessKind.Doc));
        
        accessStore[accessID].push(Object({
            idHash: CIDHash,
            idEncr: p.CIDEncr,
            keyEncr: p.keyEncr,
            level: AccessLevel.Admin
        }));
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
        bytes  calldata CID,
        Object calldata accessObj,
        address         userAddr,
        uint            nonce,
        address         signer,
        bytes calldata  signature
    ) 
        external checkNonce(signer, nonce) 
    {    
        // Signature verification
        bytes32 payloadHash = keccak256(abi.encode("setDocAccess", CID, accessObj, userAddr, nonce));
        require(SignChecker.signCheck(payloadHash, signer, signature), "SIG");

        User memory user = users[userAddr];
        require(user.id != bytes32(0), "NFD");
        require(users[signer].id != bytes32(0), "NFD");

        // Checking access rights
        {
            // Signer should be Owner or Admin of doc
            bytes32 CIDHash = keccak256(abi.encode(CID));
            AccessLevel signerLevel = getUserAccessLevel(users[signer].id, AccessKind.Doc, CIDHash);
            require(signerLevel == AccessLevel.Owner || signerLevel == AccessLevel.Admin, "DND");
            require(getUserAccessLevel(user.id, AccessKind.Doc, CIDHash) != AccessLevel.Owner, "DND");
        }
        
        // Request validation
        if (accessObj.level == AccessLevel.NoAccess) {
            require(accessObj.keyEncr.length == 0 && accessObj.idEncr.length == 0, "E01");
        }

        // Set access
        accessStore[keccak256(abi.encode(user.id, AccessKind.Doc))].push(accessObj);
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
