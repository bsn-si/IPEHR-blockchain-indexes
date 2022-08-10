pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Multicall.sol";

contract EhrIndexer is Ownable, Multicall {
  /** 
    Error codes:
    ADL - already deleted
    WTP - wrong type passed
  */

  enum DocType { Ehr, EhrAccess, EhrStatus , Composition }
  enum DocStatus { Active, Deleted }

  struct DocumentMeta {
    DocType docType;
    DocStatus status;
    bytes32 cID;
    bytes32 docBaseUIDHash;
    bytes32 version;
    bytes   docUIDEncrypted;
    bool    isLast;
    uint32  timestamp;
  }

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
  mapping (bytes32  => mapping(DocType => DocumentMeta[])) public ehrDocs; // ehr_id -> docType -> DocumentMeta[]
  mapping (bytes32  => bytes32) public ehrUsers; // userId -> EHRid
  mapping (bytes32  => bytes32) public ehrSubject;  // subjectKey -> ehr_id
  mapping (bytes32  => bytes) public docAccess;
  mapping (bytes32  => bytes) public dataAccess;
  mapping (address => bool) public allowedChange;

  event EhrSubjectSet(bytes32  subjectKey, bytes32  ehrId);
  event EhrDocAdded(bytes32  ehrId, bytes32 cId);
  event DocAccessChanged(bytes32  userId, bytes access);
  event DataAccessChanged(bytes32  userId, bytes access);

  modifier onlyAllowed(address _addr) {
    require(allowedChange[_addr] == true, "Not allowed");
    _;
  }

  function setAllowed(address addr, bool allowed) external onlyOwner() returns (bool) {
    allowedChange[addr] = allowed;
    return true;
  }

  function setEhrUser(bytes32 userId, bytes32 ehrId) external onlyAllowed(msg.sender) returns (bytes32) {
    ehrUsers[userId] = ehrId;
    return ehrId;
  }

  function addEhrDoc(bytes32 ehrId, DocumentMeta memory docMeta) external onlyAllowed(msg.sender) {
      if (docMeta.docType == DocType.Ehr) {
        if (ehrDocs[ehrId][DocType.Ehr].length > 0) revert("Ehr already exists");
      }

      if (docMeta.docType == DocType.Composition) {
        for (uint256 index = 0; index < ehrDocs[ehrId][docMeta.docType].length; index++) {
          if (ehrDocs[ehrId][docMeta.docType][index].docType == DocType.Composition) ehrDocs[ehrId][docMeta.docType][index].isLast = false;
        }
        docMeta.isLast = true;
      }
      ehrDocs[ehrId][docMeta.docType].push(docMeta);
      emit EhrDocAdded(ehrId, docMeta.cID);
  }

  function getEhrDocs(bytes32 ehrId, DocType docType) public view returns(DocumentMeta[] memory) {
    return ehrDocs[ehrId][docType];
  }

  function setEhrSubject(bytes32 subjectKey, bytes32 _ehrId) external onlyAllowed(msg.sender) returns (bytes32) {
    ehrSubject[subjectKey] = _ehrId;
    emit EhrSubjectSet(subjectKey, _ehrId);
    return _ehrId;
  }

  function setDocAccess(bytes32 userId, bytes memory _access) external onlyAllowed(msg.sender) returns (bytes32) {
    docAccess[userId] = _access;
    emit DocAccessChanged(userId, _access);
    return userId;
  }

  function setDataAccess(bytes32 userId, bytes memory _access) external onlyAllowed(msg.sender) returns (bytes32) {
    dataAccess[userId] = _access;
    emit DataAccessChanged(userId, _access);
    return userId;
  }

  function getLastEhrDocByType(bytes32 ehrId, DocType docType) public view returns(DocumentMeta memory docMeta) {
    for (uint256 index = 0; index < ehrDocs[ehrId][docType].length; index++) {
      if (ehrDocs[ehrId][docType][index].isLast == true) return ehrDocs[ehrId][docType][index];
    }
  }

  function deleteDoc(bytes32 ehrId, DocType docType, bytes32 docBaseUIDHash, bytes32 version) external onlyAllowed(msg.sender) {
    require(docType == DocType.Composition, "WTP");
    uint256 foundIndex;
    for (uint256 index = 0; index < ehrDocs[ehrId][docType].length; index++) {
      if (ehrDocs[ehrId][docType][index].docBaseUIDHash == docBaseUIDHash &&
      ehrDocs[ehrId][docType][index].version == version) foundIndex = index;
    }
    require (ehrDocs[ehrId][docType][foundIndex].status != DocStatus.Deleted, "ADL");
    ehrDocs[ehrId][docType][foundIndex].status = DocStatus.Deleted;
  }

  function getDocByVersion(bytes32 ehrId, DocType docType, bytes32 docBaseUIDHash, bytes32 version) public view returns (DocumentMeta memory docMeta) {
    for (uint256 index = 0; index < ehrDocs[ehrId][docType].length; index++) {
      if (ehrDocs[ehrId][docType][index].docBaseUIDHash == docBaseUIDHash &&
      ehrDocs[ehrId][docType][index].version == version) return ehrDocs[ehrId][docType][index];
    }
  }

  function getDocLastByBaseID(bytes32 ehrId, DocType docType, bytes32 docBaseUIDHash) public view returns (DocumentMeta memory _docMeta) {
    DocumentMeta memory docMeta;
    for (uint256 index = 0; index < ehrDocs[ehrId][docType].length; index++) {
      if (ehrDocs[ehrId][docType][index].docBaseUIDHash == docBaseUIDHash) docMeta = ehrDocs[ehrId][docType][index];
    }
    return docMeta;
  }

  function getDocByTime(bytes32 ehrId, DocType docType, uint32 timestamp) public view returns (DocumentMeta memory _docMeta) {
    DocumentMeta memory docMeta;
    for (uint256 index = 0; index < ehrDocs[ehrId][docType].length; index++) {
      if (ehrDocs[ehrId][docType][index].timestamp <= timestamp) docMeta = ehrDocs[ehrId][docType][index];
    }
    return docMeta;
  }
}
