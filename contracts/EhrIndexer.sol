pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Multicall.sol";

contract EhrIndexer is Ownable, Multicall {
  enum DocType { Ehr, EhrAccess, EhrStatus , Composition }

  struct DocumentMeta {
    DocType docType;
    uint8 status;
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
  mapping (uint256 => DocumentMeta[]) public ehrDocs; // ehr_id -> DocumentMeta[]
  mapping (uint256 => uint256) public ehrUsers; // userId -> EHRid
  mapping (uint256 => uint256) public ehrSubject;  // subjectKey -> ehr_id
  mapping (uint256 => bytes) public docAccess;
  mapping (uint256 => bytes) public dataAccess;
  mapping (address => bool) public allowedChange;

  event EhrSubjectSet(uint256 subjectKey, uint256 ehrId);
  event EhrDocAdded(uint256 ehrId, bytes32 cId);
  event DocAccessChanged(uint256 userId, bytes access);
  event DataAccessChanged(uint256 userId, bytes access);

  modifier onlyAllowed(address _addr) {
    require(allowedChange[_addr] == true, "Not allowed");
    _;
  }

  function setAllowed(address addr, bool allowed) external onlyOwner() returns (bool) {
    allowedChange[addr] = allowed;
    return true;
  }

  function setEhrUser(uint256 userId, uint256 ehrId) external onlyAllowed(msg.sender) returns (uint256) {
    ehrUsers[userId] = ehrId;
    return ehrId;
  }

  function addEhrDoc(uint256 ehrId, DocumentMeta memory docMeta) external onlyAllowed(msg.sender) {
      bool ehrAlreadyExists = false;
      if (docMeta.docType == DocType.Ehr) {
        for (uint256 index = 0; index < ehrDocs[ehrId].length; index++) {
          if (ehrDocs[ehrId][index].docType == DocType.Ehr) ehrAlreadyExists = true;
        }
      }
      require(!ehrAlreadyExists, "Ehr already exists");

      if (docMeta.docType == DocType.Composition) {
        for (uint256 index = 0; index < ehrDocs[ehrId].length; index++) {
          if (ehrDocs[ehrId][index].docType == DocType.Composition) ehrDocs[ehrId][index].isLast = false;
        }
        docMeta.isLast = true;
      }
      ehrDocs[ehrId].push(docMeta);
      emit EhrDocAdded(ehrId, docMeta.cID);
  }

  function getEhrDocs(uint256 ehrId) public view returns(DocumentMeta[] memory) {
    return ehrDocs[ehrId];
  }

  function setEhrSubject(uint256 subjectKey, uint256 _ehrId) external onlyAllowed(msg.sender) returns (uint256) {
    ehrSubject[subjectKey] = _ehrId;
    emit EhrSubjectSet(subjectKey, _ehrId);
    return _ehrId;
  }

  function setDocAccess(uint256 userId, bytes memory _access) external onlyAllowed(msg.sender) returns (uint256) {
    docAccess[userId] = _access;
    emit DocAccessChanged(userId, _access);
    return userId;
  }

  function setDataAccess(uint256 userId, bytes memory _access) external onlyAllowed(msg.sender) returns (uint256) {
    dataAccess[userId] = _access;
    emit DataAccessChanged(userId, _access);
    return userId;
  }

  function getLastEhrDocByType(uint256 ehrId, DocType docType) public view returns(DocumentMeta memory) {
    uint256 lastFoundIndex;
    for (uint256 index = 0; index < ehrDocs[ehrId].length; index++) {
      if (ehrDocs[ehrId][index].docType == docType) lastFoundIndex = index;
    }
    return ehrDocs[ehrId][lastFoundIndex];
  }
} 
