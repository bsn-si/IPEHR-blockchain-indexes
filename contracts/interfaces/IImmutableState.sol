// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

interface IImmutableState {
    function accessStore() external view returns (address);
    function users() external view returns (address);
}
