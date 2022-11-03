// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.4;

import "./EhrRestrictable.sol";
import "./SignChecker.sol";

contract EhrAccess is EhrRestrictable {
    enum AccessLevel { NoAccess, Owner, Admin, Read }

    struct Access {
        AccessLevel   level;
        bytes       keyEncrypted;
    }

    mapping (bytes32 => Access) public accessStore;
}
