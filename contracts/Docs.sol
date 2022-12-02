// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./Users.sol";

contract Docs is Users {

    enum DocType {
        Ehr,            // 0
        EhrAccess,      // 1
        EhrStatus ,     // 2
        Composition,    // 3
        Query           // 4
    
    }
    enum DocStatus { 
        Active,         // 0
        Deleted         // 1
    }

    struct DocumentMeta {
        DocStatus   status;
        bytes       id;
        bytes       version;
        uint32      timestamp;
        bool        isLast;
        Attributes.Attribute[] attrs; 
    }

    mapping (bytes32  => mapping(DocType => DocumentMeta[])) ehrDocs; // ehr_id -> docType -> DocumentMeta[]
    mapping (bytes32  => bytes32) public ehrSubject;  // subjectKey -> ehr_id
    mapping (bytes32 => bool) cids;

    ///
    function setEhrSubject(
        bytes32 subjectKey, 
        bytes32 ehrId,
        address signer, 
        bytes calldata signature
    ) 
        external onlyAllowed(msg.sender)
    {
        signCheck(signer, signature);
        ehrSubject[subjectKey] = ehrId;
    }

    ///
    function setEhrDocAttr(
        bytes32 ehrId, 
        DocType docType, 
        uint index, 
        Attributes.Code attrCode, 
        bytes memory value
    ) 
        private
    {
        for (uint i = 0; i < ehrDocs[ehrId][docType][index].attrs.length; i++) {
            if (ehrDocs[ehrId][docType][index].attrs[i].code == attrCode) {
                ehrDocs[ehrId][docType][index].attrs[i].value = value;
                return;
            }
        }
    }

    struct AddEhrDocParams {
        DocType     docType;
        bytes       id;
        bytes       version;
        uint32      timestamp;
        Attributes.Attribute[] attrs;
        address     signer;
        bytes       signature;
    }
    
    ///
    function addEhrDoc(AddEhrDocParams calldata p) 
        external onlyAllowed(msg.sender) 
    {
        signCheck(p.signer, p.signature);

        bytes32 userId = users[p.signer].id;
        require(userId != bytes32(0), "NFD1");

        bytes32 ehrId = ehrUsers[userId];
        require(ehrId != bytes32(0), "NFD2");

        require(p.id.length > 0, "REQ1");

        bytes32 IDHash = keccak256(p.id);
        require(cids[IDHash] == false, "AEX");
        cids[IDHash] = true;

        ehrDocs[ehrId][p.docType].push();
        DocumentMeta storage docMeta = ehrDocs[ehrId][p.docType][ehrDocs[ehrId][p.docType].length - 1];

        if (p.docType == DocType.Ehr || p.docType == DocType.EhrStatus) {
            for (uint i = 0; i < ehrDocs[ehrId][p.docType].length; i++) {
                ehrDocs[ehrId][p.docType][i].isLast = false;
            }
        } else if (p.docType == DocType.Composition || p.docType == DocType.Query) {
            bytes32 docBaseUIDHash = bytes32(Attributes.get(p.attrs, Attributes.Code.DocBaseUIDHash));
            for (uint i = 0; i < ehrDocs[ehrId][p.docType].length; i++) {
                if (bytes32(Attributes.get(ehrDocs[ehrId][p.docType][i].attrs, Attributes.Code.DocBaseUIDHash)) == docBaseUIDHash) {
                    ehrDocs[ehrId][p.docType][i].isLast = false;
                }
            }
        }

        docMeta.status = DocStatus.Active;
        docMeta.id = p.id;
        docMeta.version = p.version;
        docMeta.timestamp = p.timestamp;
        docMeta.isLast = true;

        for (uint i; i < p.attrs.length; i++) {
            docMeta.attrs.push(p.attrs[i]);
        }

        if (p.docType == DocType.Query) return;
        
        setAccess(keccak256(abi.encode(userId, AccessKind.Doc)), Access({
            idHash: IDHash,
            idEncr: Attributes.get(p.attrs, Attributes.Code.IDEncr),
            keyEncr: Attributes.get(p.attrs, Attributes.Code.KeyEncr),
            level: AccessLevel.Admin
        }));
    }

    ///
    function getEhrDocs(bytes32 ehrId, DocType docType) public view returns(DocumentMeta[] memory) 
    {
        return ehrDocs[ehrId][docType];
    }

    ///
    function getLastEhrDocByType(bytes32 ehrId, DocType docType) public view returns(DocumentMeta memory) {
        for (uint i = 0; i < ehrDocs[ehrId][docType].length; i++) {
            if (ehrDocs[ehrId][docType][i].isLast == true ) {
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
            if (bytes32(Attributes.get(ehrDocs[ehrId][docType][i].attrs, Attributes.Code.DocBaseUIDHash)) == docBaseUIDHash && 
                bytes32(ehrDocs[ehrId][docType][i].version) == version) return ehrDocs[ehrId][docType][i];
        }
        revert("NFD");
    }

    ///
    function getDocByTime(bytes32 ehrID, DocType docType, uint32 timestamp)
        public view returns (DocumentMeta memory)
    {
        for (uint i = 0; i < ehrDocs[ehrID][docType].length; i++) {
            if (ehrDocs[ehrID][docType][i].timestamp <= timestamp && ehrDocs[ehrID][docType][i].timestamp > 0) {
                return ehrDocs[ehrID][docType][i];
            } 
        }

        revert("NFD");
    }

    ///
    function getDocLastByBaseID(
        bytes32 ehrId, 
        DocType docType, 
        bytes32 docBaseUIDHash
    ) 
        public view returns (DocumentMeta memory) 
    {
        for (uint i = 0; i < ehrDocs[ehrId][docType].length; i++) {
            if (bytes32(Attributes.get(ehrDocs[ehrId][docType][i].attrs, Attributes.Code.DocBaseUIDHash)) == docBaseUIDHash && 
                ehrDocs[ehrId][docType][i].isLast) return ehrDocs[ehrId][docType][i];
        }

        revert("NFD");
    }

    ///
    function setDocAccess(
        bytes32         CIDHash,
        Access calldata access,
        address         userAddr,
        address         signer,
        bytes calldata  signature
    ) 
        external 
    {    
        signCheck(signer, signature);

        User memory user = users[userAddr];
        require(user.id != bytes32(0), "NFD");
        require(users[signer].id != bytes32(0), "NFD");

        // Checking access rights
        {
            // Signer should be Owner or Admin of doc
            AccessLevel signerLevel = userAccess(users[signer].id, AccessKind.Doc, CIDHash).level;
            require(signerLevel == AccessLevel.Owner || signerLevel == AccessLevel.Admin, "DND");
            require(userAccess(user.id, AccessKind.Doc, CIDHash).level != AccessLevel.Owner, "DND");
        }
        
        // Request validation
        if (access.level == AccessLevel.NoAccess) {
            require(access.keyEncr.length == 0 && access.idEncr.length == 0, "E01");
        }

        // Set access
        setAccess(keccak256(abi.encode(user.id, AccessKind.Doc)), access);
    }

    ///
    function deleteDoc(
        bytes32 ehrId, 
        DocType docType, 
        bytes32 docBaseUIDHash, 
        bytes32 version,
        address signer,
        bytes calldata  signature
    ) 
        external onlyAllowed(msg.sender)
    {
        signCheck(signer, signature);

        require(docType == DocType.Composition, "WTP");
        
        for (uint i = 0; i < ehrDocs[ehrId][docType].length; i++) {
            if (bytes32(Attributes.get(ehrDocs[ehrId][docType][i].attrs, Attributes.Code.DocBaseUIDHash)) == docBaseUIDHash && 
                bytes32(ehrDocs[ehrId][docType][i].version) == version) 
            {
                require (ehrDocs[ehrId][docType][i].status != DocStatus.Deleted, "ADL");
                ehrDocs[ehrId][docType][i].status = DocStatus.Deleted;
                return;
            }
        }
        revert("NFD");
    }
}
