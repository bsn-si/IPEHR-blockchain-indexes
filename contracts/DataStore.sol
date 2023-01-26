// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./libraries/Attributes.sol";

import "./interfaces/IUsers.sol";
import "./interfaces/IDocs.sol";

import "./ImmutableState.sol";
import "./Restrictable.sol";

contract DataStore is ImmutableState, Restrictable {

    constructor(address _accessStore, address _users, address _ehrIndex) ImmutableState(_accessStore, _users, _ehrIndex) {}

    struct DataSet  {
        bytes   data;
        Attributes.Attribute[] attrs;
    }

    mapping (bytes32 => DataSet) dataStore;     // dataHash -> DataSet

    event DataUpdate(bytes data);

    ///
    function dataUpdate(
        Attributes.Attribute[] calldata attrs, 
        address signer, 
        bytes calldata signature
    ) 
        external 
    {
        signCheck(signer, signature);

        require(IUsers(users).getUser(signer).IDHash != bytes32(0), "NFD");

        bytes memory data = Attributes.get(attrs, Attributes.Code.Content);
        require(data.length > 0, "LEN");

        bytes32 dataHash = keccak256(abi.encode(data));
        require(dataStore[dataHash].data.length == 0, "AEX");

        dataStore[dataHash].data = data;

        for (uint i; i < attrs.length; i++) {
            dataStore[dataHash].attrs.push(attrs[i]);
        }

        emit DataUpdate(data);
    }
}
