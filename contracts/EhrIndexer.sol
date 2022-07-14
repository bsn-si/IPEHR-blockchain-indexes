pragma solidity ^0.8.0;

import "hardhat/console.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract EhrIndexer is Ownable {
  struct DocumentMeta {
    uint8 docType;
    uint8 status;
    uint256 storageId;
    bytes docIdEncrypted;
    uint32 timestamp;
  }

  mapping (uint256 => DocumentMeta[]) public ehrDocs; // ehr_id -> DocumentMeta[]
  mapping (uint256 => uint256) public ehrUsers; // userId -> EHRid
  mapping (uint256 => uint256) public ehrSubject;  // subjectKey -> ehr_id
  mapping (uint256 => bytes) public docAccess;
  mapping (uint256 => bytes) public dataAccess;
  mapping (address => bool) public allowedChange;

  event EhrSubjectSet(uint256 subjectKey, uint256 ehrId);
  event EhrDocSet(uint256 ehrId, uint256 docKey);
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

  function setEhrDoc(
    uint256 ehrId,
    uint256 docKey,
    uint8 _docType,
    uint8 _status,
    uint256 _storageId,
    bytes memory _docIdEncrypted,
    uint32 _timestamp) external onlyAllowed(msg.sender) returns (uint256) {
      DocumentMeta storage doc = ehrDocs[ehrId][docKey];
      doc.docType = _docType;
      doc.status = _status;
      doc.storageId = _storageId;
      doc.docIdEncrypted = _docIdEncrypted;
      doc.timestamp = _timestamp;
      emit EhrDocSet(ehrId, docKey);
      return docKey;
  }

  function addEhrDoc(
    uint256 ehrId,
    uint8 _docType,
    uint8 _status,
    uint256 _storageId,
    bytes memory _docIdEncrypted,
    uint32 _timestamp) external onlyAllowed(msg.sender) returns (uint256) {
      DocumentMeta memory doc;
      doc.docType = _docType;
      doc.status = _status;
      doc.storageId = _storageId;
      doc.docIdEncrypted = _docIdEncrypted;
      doc.timestamp = _timestamp;
      ehrDocs[ehrId].push(doc);
      return ehrDocs[ehrId].length;
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
}
