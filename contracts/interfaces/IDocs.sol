// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17;

import "../libraries/Attributes.sol";

interface IDocs {
    enum Type {
        Ehr,            // 0
        EhrAccess,      // 1
        EhrStatus ,     // 2
        Composition,    // 3
        Query,          // 4
        Template,       // 5
        Directory       // 6
    }

    enum Status { 
        Active,         // 0
        Deleted         // 1
    }

    struct DocumentMeta {
        Status   status;
        bytes    id;
        bytes    version;
        uint32   timestamp;
        bool     isLast;
        Attributes.Attribute[] attrs; 
    }

    struct AddEhrDocParams {
        Type        docType;
        bytes       id;
        bytes       version;
        uint32      timestamp;
        Attributes.Attribute[] attrs;
        address     signer;
        uint        deadline;
        bytes       signature;
    }

    function getLastEhrDocByType(bytes32 ehrID, Type docType) external view returns(DocumentMeta memory);
}
