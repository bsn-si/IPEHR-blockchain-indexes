// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./interfaces/IUsers.sol";
import "./interfaces/IDocs.sol";
import "./ImmutableState.sol";
import "./Restrictable.sol";

abstract contract Docs is ImmutableState, Restrictable {

    mapping (bytes32  => mapping(IDocs.Type => IDocs.DocumentMeta[])) ehrDocs; // ehr_id -> docType -> DocumentMeta[]
    mapping (bytes32 => bytes32) ehrUsers;              // userID -> ehrID
    mapping (bytes32  => bytes32) public ehrSubject;    // subjectKey -> ehr_id
    mapping (bytes32 => bool) private cids;

    ///
    function setEhrUser(
        bytes32 IDHash,
        bytes32 ehrId,
        address signer,
        uint deadline,
        bytes calldata signature
    )
        external onlyAllowed(msg.sender)
    {
        signCheck(signer, deadline, signature);
        require(ehrUsers[IDHash] == bytes32(0), "AEX");
        ehrUsers[IDHash] = ehrId;
    }

    ///
    function getEhrUser(bytes32 userIDHash) public view returns(bytes32) {
        return ehrUsers[userIDHash];
    }

    ///
    function setEhrSubject(
        bytes32 subjectKey,
        bytes32 ehrId,
        address signer,
        uint deadline,
        bytes calldata signature
    )
        external onlyAllowed(msg.sender)
    {
        signCheck(signer, deadline, signature);
        ehrSubject[subjectKey] = ehrId;
    }

    ///
    function setEhrDocAttr(
        bytes32 ehrId,
        IDocs.Type docType,
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

    ///
    function addEhrDoc(IDocs.AddEhrDocParams calldata p)
        external onlyAllowed(msg.sender)
    {
        signCheck(p.signer, p.deadline, p.signature);

        bytes32 userIDHash = IUsers(users).getUser(p.signer).IDHash;
        require(userIDHash != bytes32(0), "NFD1");

        bytes32 ehrId = ehrUsers[userIDHash];
        require(ehrId != bytes32(0), "NFD2");

        require(p.id.length > 0, "REQ1");

        bytes32 IDHash = keccak256(p.id);
        require(cids[IDHash] == false, "AEX");
        cids[IDHash] = true;

        uint i;

        if (p.docType == IDocs.Type.Ehr || p.docType == IDocs.Type.EhrStatus) {
            for (i = 0; i < ehrDocs[ehrId][p.docType].length; i++) {
                ehrDocs[ehrId][p.docType][i].isLast = false;
            }
        } else if (p.docType != IDocs.Type.Ehr && p.docType != IDocs.Type.EhrAccess && p.docType != IDocs.Type.EhrStatus) {
            bytes32 docBaseUIDHash;

            for (i = 0; i < p.attrs.length; i++) {
                if (p.attrs[i].code == Attributes.Code.DocBaseUIDHash) {
                    docBaseUIDHash = bytes32(p.attrs[i].value);
                    break;
                }
            }
            require(docBaseUIDHash != bytes32(0), "REQ2");

            for (i = 0; i < ehrDocs[ehrId][p.docType].length; i++) {
                if (bytes32(Attributes.get(ehrDocs[ehrId][p.docType][i].attrs, Attributes.Code.DocBaseUIDHash)) == docBaseUIDHash) {
                    ehrDocs[ehrId][p.docType][i].isLast = false;
                }
            }
        }

        ehrDocs[ehrId][p.docType].push();
        IDocs.DocumentMeta storage docMeta = ehrDocs[ehrId][p.docType][ehrDocs[ehrId][p.docType].length - 1];

        docMeta.status = IDocs.Status.Active;
        docMeta.id = p.id;
        docMeta.version = p.version;
        docMeta.timestamp = p.timestamp;
        docMeta.isLast = true;

        for (i = 0; i < p.attrs.length; i++) {
            if (
                p.attrs[i].code == Attributes.Code.IDEncr
                //p.attrs[i].code == Attributes.Code.KeyEncr - used with Compositions GetList. Otherwise we mast to search for them in AccessStore
            ) continue;

            docMeta.attrs.push(p.attrs[i]);
        }

        if (p.docType == IDocs.Type.Query) return;

        /*
        IAccessStore(accessStore).setAccess(
            keccak256(abi.encode(userIDHash, IAccessStore.AccessKind.Doc)),
            IAccessStore.Access({
                idHash: IDHash,
                idEncr: Attributes.get(p.attrs, Attributes.Code.IDEncr),
                keyEncr: Attributes.get(p.attrs, Attributes.Code.KeyEncr),
                level: IAccessStore.AccessLevel.Admin
            }
        ));
        */
    }

    ///
    function getEhrDocs(bytes32 userIDHash, IDocs.Type docType) public view returns(IDocs.DocumentMeta[] memory)
    {
        bytes32 ehrId = getEhrUser(userIDHash);
        require(ehrId != bytes32(0), "NFD");

        return ehrDocs[ehrId][docType];
    }

    ///
    function getLastEhrDocByType(bytes32 ehrId, IDocs.Type docType) public view returns(IDocs.DocumentMeta memory) {
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
        IDocs.Type docType,
        bytes32 docBaseUIDHash,
        bytes32 version
    )
        public view returns (IDocs.DocumentMeta memory)
    {
        for (uint i = 0; i < ehrDocs[ehrId][docType].length; i++) {
            if (bytes32(Attributes.get(ehrDocs[ehrId][docType][i].attrs, Attributes.Code.DocBaseUIDHash)) == docBaseUIDHash &&
                bytes32(ehrDocs[ehrId][docType][i].version) == version) return ehrDocs[ehrId][docType][i];
        }
        revert("NFD");
    }

    ///
    function getDocByTime(bytes32 ehrID, IDocs.Type docType, uint32 timestamp)
    public view returns (IDocs.DocumentMeta memory)
    {
        uint len = ehrDocs[ehrID][docType].length;
        require(len != 0, "NFD");

        for (uint i = len-1; i >= 0; --i) {
            if (ehrDocs[ehrID][docType][i].timestamp <= timestamp && ehrDocs[ehrID][docType][i].timestamp > 0) {
                return ehrDocs[ehrID][docType][i];
            }
        }

        revert("NFD");
    }

    ///
    function getDocLastByBaseID(
        bytes32    userIDHash,
        IDocs.Type docType,
        bytes32    UIDHash
    )
        public view returns (IDocs.DocumentMeta memory)
    {
        bytes32 ehrId = ehrUsers[userIDHash];
        require(ehrId != bytes32(0), "NFD1");

        for (uint i = 0; i < ehrDocs[ehrId][docType].length; i++) {
            if (bytes32(Attributes.get(ehrDocs[ehrId][docType][i].attrs, Attributes.Code.DocBaseUIDHash)) == UIDHash &&
                ehrDocs[ehrId][docType][i].isLast) return ehrDocs[ehrId][docType][i];
        }

        revert("NFD2");
    }

    ///
    function deleteDoc(
        bytes32    ehrId,
        IDocs.Type docType,
        bytes32    docBaseUIDHash,
        bytes32    version,
        address    signer,
        uint deadline,
        bytes calldata  signature
    )
        external onlyAllowed(msg.sender)
    {
        signCheck(signer, deadline, signature);

        require(docType == IDocs.Type.Composition || docType == IDocs.Type.Directory, "WTP");

        for (uint i = 0; i < ehrDocs[ehrId][docType].length; i++) {
            if (bytes32(Attributes.get(ehrDocs[ehrId][docType][i].attrs, Attributes.Code.DocBaseUIDHash)) == docBaseUIDHash &&
                bytes32(ehrDocs[ehrId][docType][i].version) == version)
            {
                require (ehrDocs[ehrId][docType][i].status != IDocs.Status.Deleted, "ADL");
                ehrDocs[ehrId][docType][i].status = IDocs.Status.Deleted;
                return;
            }
        }
        revert("NFD");
    }
}
