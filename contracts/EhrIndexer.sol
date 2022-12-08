// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/utils/Multicall.sol";
import "./Users.sol";
import "./Access.sol";
import "./Docs.sol";
import "./DocGroups.sol";

contract EhrIndexer is Multicall, Users, Docs, DocGroups {
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

}
