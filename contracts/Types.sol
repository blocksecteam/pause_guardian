// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.17;


/// @dev Use enum instead of bool in case of when other status, like PENDING,
///      is needed in the future.
enum AuthResult {
    FAILED,
    SUCCESS
}

enum AuthFailedReason {
    INVALID_DATA_LENGTH,
    NOT_ALLOWED_FUNC,
    NOT_ALLOWED_FUNC_PARAM
}

struct AuthorizerReturnData {
    AuthResult result;
    AuthFailedReason reason;
}

struct TransactionResult {
    bool success; // Call status.
    bytes data; // Return/Revert data.
}

struct TransactionData {
    uint256 flag; // 0x1 delegate call, 0x0 call
    address to;
    uint256 value;
    bytes data; // calldata
}

library TxFlags {
    uint256 internal constant DELEGATE_CALL_MASK = 0x1; // 1 for delegatecall, 0 for call

    function isDelegateCall(uint256 flag) internal pure returns (bool) {
        return flag & DELEGATE_CALL_MASK > 0;
    }
}


contract Enum {
    enum Operation {
        Call,
        DelegateCall
    }
}