// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/utils/Multicall.sol";
import "./Docs.sol";
import "./DocGroups.sol";
import "./ImmutableState.sol";

contract EhrIndexer is Multicall, Docs, DocGroups {
    /**
      Error codes:
      REQ - incorrect request
      ADL - already deleted
      WTP - wrong type passed
      LST - new version of the EHR document must be the latest
      NFD - not found
      AEX - already exists
      DND - access denied
      TMT - timeout
      NNC - wrong nonce
      SIG - invalid signature
      LEN - incorrect length
      OWN - caller is not the owner
  */

  constructor(address _accessStore, address _users) ImmutableState(_accessStore, _users, address(this)) {}
}
