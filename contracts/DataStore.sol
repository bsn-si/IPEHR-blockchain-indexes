// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./libraries/Attributes.sol";

import "./interfaces/IUsers.sol";

import "./ImmutableState.sol";
import "./Restrictable.sol";

contract DataStore is ImmutableState, Restrictable {

    constructor(address _users) ImmutableState(address(uint160(0)), _users, address(uint160(0))) {}

    struct DataSet  {
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
        require(Attributes.get(dataStore[dataHash].attrs, Attributes.Code.Content).length == 0, "AEX");

        for (uint i; i < attrs.length; i++) {
            dataStore[dataHash].attrs.push(attrs[i]);
        }

        emit DataUpdate(data);
    }
}
