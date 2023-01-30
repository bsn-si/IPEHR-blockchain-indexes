// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./interfaces/IUsers.sol";

import "./ImmutableState.sol";
import "./Restrictable.sol";

contract DataStore is ImmutableState, Restrictable {

    constructor(address _users) ImmutableState(address(uint160(0)), _users, address(uint160(0))) {}

    mapping(bytes32 => bool) private history;

    event DataUpdate(bytes32 groupID, bytes32 dataID, bytes32 ehrID, bytes data);

    ///
    function dataUpdate(
        bytes32 groupID,
        bytes32 dataID,
        bytes32 ehrID,      // TODO remove after Treeindex refactoring
        bytes calldata data,
        address signer,
        bytes calldata signature
    )
        external onlyAllowed(msg.sender) 
    {
        signCheck(signer, signature);

        require(IUsers(users).getUser(signer).IDHash != bytes32(0), "NFD");
        require(data.length > 0, "LEN");

        bytes32 dataHash = keccak256(abi.encode(dataID, data));
        require(history[dataHash] == false, "AEX");

        history[dataHash] = true;

        emit DataUpdate(groupID, dataID, ehrID, data);
    }
}
