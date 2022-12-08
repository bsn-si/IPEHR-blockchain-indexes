// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "./interfaces/IImmutableState.sol";

abstract contract ImmutableState is IImmutableState {
    address public immutable accessStore;
    address public immutable users;

    constructor(address _accessStore, address _users) {
        accessStore = _accessStore;
        users = _users;
    }
}
