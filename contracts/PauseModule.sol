// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "./Types.sol";


interface IGnosisSafe {
    /// @dev Allows a Module to execute a Safe transaction without any further confirmations and return data
    function execTransactionFromModuleReturnData(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) external returns (bool success, bytes memory returnData);

    function enableModule(address module) external;

    function isModuleEnabled(address module) external view returns (bool);
}

contract PauseModule is Ownable {
    using TxFlags for uint256;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.UintSet;

    bytes32 public constant NAME = "PauseModule";
    uint256 public constant VERSION = 1;

    /// @dev Tracks the set of contract address.
    EnumerableSet.AddressSet contractSet;
    /// @dev `contract address` => `function selectors`
    mapping(address => EnumerableSet.Bytes32Set) allowContractToFuncs;

    /// @dev `keccak256(address + function selector)` => `allowed function parameter offsets`
    /// @notice Parameter offset starts from 0
    mapping(bytes32 => EnumerableSet.UintSet) confinedFuncParamOffsets;
    /// @dev `keccak256(address + function selector + parameter offset)` => `allowed function parameters`
    /// @notice Supported parameter types: address, intN/uintN, bool
    mapping(bytes32 => EnumerableSet.Bytes32Set) allowedFuncParams;

    EnumerableSet.AddressSet delegates;
    bool public initialized = false;

    /// Events
    event ContractFuncSigAdded(address indexed _contract, bytes4 indexed funcSig, address indexed sender);
    event ContractFuncAdded(address indexed _contract, string func, address indexed sender);

    event ContractFuncSigRemoved(address indexed _contract, bytes4 indexed funcSig, address indexed sender);
    event ContractFuncRemoved(address indexed _contract, string func, address indexed sender);

    event FuncSigParamAdded(
        address indexed _contract,
        bytes4 indexed funcSig,
        uint256 indexed paramOffset,
        bytes32 paramValue,
        address sender
    );

    event FuncParamAdded(address indexed _contract, string func, uint256 indexed paramOffset, bytes32 paramValue, address sender);

    event FuncSigParamRemoved(
        address indexed _contract,
        bytes4 indexed funcSig,
        uint256 indexed paramOffset,
        bytes32 paramValue,
        address sender
    );
    event FuncParamRemoved(address indexed _contract, string func, uint256 indexed paramOffset, bytes32 paramValue, address sender);

    event DelegateAdded(address indexed delegate, address indexed sender);
    event DelegateRemoved(address indexed delegate, address indexed sender);
    event TransactionExecuted(address indexed delegate, address indexed from, address indexed to, bytes data, uint256 value, uint256 flag);

    /// Errors
    error InvalidDelegate(address _delegate);
    error AlreadyInitialized(address account);
    error AuthFailed(AuthFailedReason reason);
    error EmptyList(string desc);
    error FuncAuthNotConfigured(address _contract, bytes4 funcSig);
    error FuncParamAuthNotRevoked(address _contract, bytes4 funcSig);
    error DelegateCallNotAllowed();
    error ValueNotNil();

    /// Modifier
    modifier onlyDelegate() {
        if (!hasDelegate(msg.sender)) revert InvalidDelegate(msg.sender);
        _;
    }

    /// Utility functions

    function _getSelector(bytes calldata data) internal pure returns (bytes4 selector) {
        assembly {
            selector := calldataload(data.offset)
        }
    }

    function _isAllowedSelector(address target, bytes4 selector) internal view returns (bool) {
        return allowContractToFuncs[target].contains(selector);
    }

    function _isAllowedFuncParam(address target, bytes4 funcSig, uint256 paramOffset, bytes32 param) internal view returns (bool) {
        bytes32 identifierParam = _getIdentifierParams(target, funcSig, paramOffset);
        return allowedFuncParams[identifierParam].contains(param);
    }

    function _isFuncParamAuthSet(address _contract, bytes4 funcSig) internal view returns (bool) {
        return getConfinedFuncParamOffsets(_contract, funcSig).length > 0;
    }

    function _getIdentifier(address _contract, bytes4 funcSig) internal pure returns (bytes32) {
        return keccak256(abi.encode(_contract, funcSig));
    }

    function _getIdentifierParams(address _contract, bytes4 funcSig, uint256 paramOffset) internal pure returns (bytes32) {
        return keccak256(abi.encode(_contract, funcSig, paramOffset));
    }

    function _getFuncParam(bytes calldata data, uint256 paramOffset) internal pure returns (bytes32 param) {
        uint256 offset;
        assembly {
            offset := data.offset
        }
        offset += 4 + paramOffset * 32;
        assembly {
            param := calldataload(offset)
        }
    }

    function _addDelegate(address _delegate) internal {
        if (delegates.add(_delegate)) {
            emit DelegateAdded(_delegate, msg.sender);
        }
    }

    function _removeDelegate(address _delegate) internal {
        if (delegates.remove(_delegate)) {
            emit DelegateRemoved(_delegate, msg.sender);
        }
    }

    /// @notice Function Authorization
    function checkFunc(address to, bytes calldata data) internal view returns (AuthorizerReturnData memory authData) {
        // if calldata size is less than a selector, deny it
        if (data.length < 4) {
            authData.result = AuthResult.FAILED;
            authData.reason = AuthFailedReason.INVALID_DATA_LENGTH;
            return authData;
        }

        bytes4 selector = _getSelector(data);
        if (_isAllowedSelector(to, selector)) {
            authData.result = AuthResult.SUCCESS;
        } else {
            authData.result = AuthResult.FAILED;
            authData.reason = AuthFailedReason.NOT_ALLOWED_FUNC;
        }
    }

    /// @notice Function Parameter Authorization
    function checkFuncParams(address to, bytes calldata data) internal view returns (AuthorizerReturnData memory authData) {
        // assume data.length >= 4
        bytes4 selector = _getSelector(data);

        if (!_isFuncParamAuthSet(to, selector)) {
            // if parameter authorization not configured
            authData.result = AuthResult.SUCCESS;
            return authData;
        }
        uint256[] memory paramOffsetList = getConfinedFuncParamOffsets(to, selector);

        for (uint256 index = 0; index < paramOffsetList.length; index++) {
            uint256 paramOffset = paramOffsetList[index];

            // each parameter has 32-byte length according to Contract ABI Specification
            if (data.length < 4 + (paramOffset + 1) * 32) {
                authData.result = AuthResult.FAILED;
                authData.reason = AuthFailedReason.INVALID_DATA_LENGTH;
                return authData;
            }

            bytes32 param = _getFuncParam(data, paramOffset);
            // bytes32 identifierParam = _getIdentifierParams(to, selector, paramIndex);
            // if (!allowedFuncParams[identifierParam].contains(param)) {
            if (!_isAllowedFuncParam(to, selector, paramOffset, param)) {
                authData.result = AuthResult.FAILED;
                authData.reason = AuthFailedReason.NOT_ALLOWED_FUNC_PARAM;
                return authData;
            }
        }

        // Succeed only when all function parameter authorization passed
        authData.result = AuthResult.SUCCESS;
    }

    /// View functions

    /// @notice Given a contract, list all the function selectors of this contract that could be invoked by Pause module
    /// @param _contract the contract
    /// @return list of allowed function selectors in the contract
    function getFuncsByContract(address _contract) public view returns (bytes32[] memory) {
        return allowContractToFuncs[_contract].values();
    }

    /// @notice Get all the contracts configured for Pause Module
    /// @return list of contract addresses
    function getAllContracts() public view returns (address[] memory) {
        return contractSet.values();
    }

    function getConfinedFuncParamOffsets(address _contract, bytes4 funcSig) public view returns (uint256[] memory) {
        bytes32 identifier = _getIdentifier(_contract, funcSig);
        return confinedFuncParamOffsets[identifier].values();
    }

    function getAllowedFuncParams(address _contract, bytes4 funcSig, uint256 paramOffset) public view returns (bytes32[] memory) {
        bytes32 identifierParam = _getIdentifierParams(_contract, funcSig, paramOffset);
        return allowedFuncParams[identifierParam].values();
    }

    function hasDelegate(address _delegate) public view returns (bool) {
        return delegates.contains(_delegate);
    }

    function getDelegates() external view returns (address[] memory) {
        return delegates.values();
    }

    function getFuncAuthInfo() external view returns (address[] memory _contracts, bytes32[][] memory funcSigs) {
        _contracts = getAllContracts();
        funcSigs = new bytes32[][](_contracts.length);
        for (uint256 i = 0; i < _contracts.length; i++) {
            funcSigs[i] = getFuncsByContract(_contracts[i]);
        }
    }

    function getFuncParamAuthInfo(
        address _contract,
        bytes4 funcSig
    ) external view returns (uint256[] memory paramOffsets, bytes32[][] memory paramValues) {
        paramOffsets = getConfinedFuncParamOffsets(_contract, funcSig);
        paramValues = new bytes32[][](paramOffsets.length);
        for (uint256 i = 0; i < paramOffsets.length; i++) {
            paramValues[i] = getAllowedFuncParams(_contract, funcSig, paramOffsets[i]);
        }
    }

    /// External functions

    /// @notice Can only be initialized once
    function initialize(address[] calldata _delegates, address safe) public {
        if (initialized) revert AlreadyInitialized(msg.sender);

        for (uint256 i = 0; i < _delegates.length; i++) {
            _addDelegate(_delegates[i]);
        }

        _transferOwnership(safe);
        initialized = true;
    }

    function addDelegate(address _delegate) external onlyOwner {
        _addDelegate(_delegate);
    }

    function addDelegates(address[] calldata _delegates) external onlyOwner {
        for (uint256 i = 0; i < _delegates.length; i++) {
            _addDelegate(_delegates[i]);
        }
    }

    function removeDelegate(address _delegate) external onlyOwner {
        _removeDelegate(_delegate);
    }

    function removeDelegates(address[] calldata _delegates) external onlyOwner {
        for (uint256 i = 0; i < _delegates.length; i++) {
            _removeDelegate(_delegates[i]);
        }
    }

    /// @notice Execute transaction on behalf of the Safe owner(s)
    function _execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 flag
    ) internal returns (TransactionResult memory transactionResult) {
        if (flag.isDelegateCall()) revert DelegateCallNotAllowed();
        if (value > 0) revert ValueNotNil();

        // function authorization
        AuthorizerReturnData memory FuncAuthData = checkFunc(to, data);
        if (FuncAuthData.result == AuthResult.FAILED) {
            revert AuthFailed(FuncAuthData.reason);
        }

        // function parameter authorization
        AuthorizerReturnData memory FuncParamAuthData = checkFuncParams(to, data);
        if (FuncParamAuthData.result == AuthResult.FAILED) {
            revert AuthFailed(FuncParamAuthData.reason);
        }

        // execute transaction
        (transactionResult.success, transactionResult.data) = IGnosisSafe(payable(owner())).execTransactionFromModuleReturnData(
            to,
            value,
            data,
            flag.isDelegateCall() ? Enum.Operation.DelegateCall : Enum.Operation.Call
        );
        emit TransactionExecuted(msg.sender, owner(), to, data, value, flag);
    }

    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 flag
    ) public onlyDelegate returns (TransactionResult memory result) {
        result = _execTransaction(to, value, data, flag);
    }

    /// @notice Multi-call for transaction execution
    function execTransactions(TransactionData[] calldata txDataList) external onlyDelegate returns (TransactionResult[] memory resultList) {
        resultList = new TransactionResult[](txDataList.length);

        for (uint256 i = 0; i < txDataList.length; i++) {
            TransactionData calldata txData = txDataList[i];
            resultList[i] = _execTransaction(txData.to, txData.value, txData.data, txData.flag);
        }
    }

    /// @notice Add contract and related function signature list.
    /// @dev keccak256 hash is calcuated and only 4 bytes selector is stored to reduce storage usage.
    function addContractFuncs(address _contract, string[] calldata funcList) external onlyOwner {
        if (funcList.length == 0) revert EmptyList("Empty FuncList");

        for (uint256 index = 0; index < funcList.length; index++) {
            bytes4 funcSelector = bytes4(keccak256(bytes(funcList[index])));
            bytes32 funcSelector32 = bytes32(funcSelector);
            if (allowContractToFuncs[_contract].add(funcSelector32)) {
                emit ContractFuncAdded(_contract, funcList[index], msg.sender);
                emit ContractFuncSigAdded(_contract, funcSelector, msg.sender);
            }
        }

        contractSet.add(_contract);
    }

    /// @notice Similar to `addContractFuncs()` but bytes4 selector is used.
    /// @dev keccak256 hash should be performed off-chain.
    function addContractFuncsSig(address _contract, bytes4[] calldata funcSigList) external onlyOwner {
        if (funcSigList.length == 0) revert EmptyList("Empty FuncSigList");

        for (uint256 index = 0; index < funcSigList.length; index++) {
            bytes32 funcSelector32 = bytes32(funcSigList[index]);
            if (allowContractToFuncs[_contract].add(funcSelector32)) {
                emit ContractFuncSigAdded(_contract, funcSigList[index], msg.sender);
            }
        }

        contractSet.add(_contract);
    }

    /// @notice Remove contract and its function signature list from access list.
    function removeContractFuncs(address _contract, string[] calldata funcList) external onlyOwner {
        if (funcList.length == 0) revert EmptyList("Empty FuncList");

        for (uint256 index = 0; index < funcList.length; index++) {
            bytes4 funcSelector = bytes4(keccak256(bytes(funcList[index])));
            bytes32 funcSelector32 = bytes32(funcSelector);

            // Cannot remove function while its parameter authorization is not revoked
            if (_isFuncParamAuthSet(_contract, funcSelector)) {
                revert FuncParamAuthNotRevoked(_contract, funcSelector);
            }

            if (allowContractToFuncs[_contract].remove(funcSelector32)) {
                emit ContractFuncRemoved(_contract, funcList[index], msg.sender);
                emit ContractFuncSigRemoved(_contract, funcSelector, msg.sender);
            }
        }

        if (allowContractToFuncs[_contract].length() == 0) {
            contractSet.remove(_contract);
        }
    }

    /// @notice Remove contract and its function selector list from access list.
    function removeContractFuncsSig(address _contract, bytes4[] calldata funcSigList) external onlyOwner {
        if (funcSigList.length == 0) revert EmptyList("Empty FuncSigList");

        for (uint256 index = 0; index < funcSigList.length; index++) {
            bytes4 funcSelector = funcSigList[index];
            bytes32 funcSelector32 = bytes32(funcSelector);

            // Cannot remove function while its parameter authorization is not revoked
            if (_isFuncParamAuthSet(_contract, funcSelector)) {
                revert FuncParamAuthNotRevoked(_contract, funcSelector);
            }

            if (allowContractToFuncs[_contract].remove(funcSelector32)) {
                emit ContractFuncSigRemoved(_contract, funcSigList[index], msg.sender);
            }
        }

        if (allowContractToFuncs[_contract].length() == 0) {
            contractSet.remove(_contract);
        }
    }

    function addFuncParams(
        address _contract,
        string calldata func,
        uint256 paramOffset,
        bytes32[] calldata paramValueList
    ) external onlyOwner {
        bytes4 funcSig = bytes4(keccak256(bytes(func)));
        if (paramValueList.length == 0) revert EmptyList("Empty ParamValueList");

        // Cannot configure function parameter authorization without function authorization configured
        if (!_isAllowedSelector(_contract, funcSig)) revert FuncAuthNotConfigured(_contract, funcSig);

        bytes32 identifierParam = _getIdentifierParams(_contract, funcSig, paramOffset);
        for (uint256 index = 0; index < paramValueList.length; index++) {
            bytes32 paramValue = paramValueList[index];
            if (allowedFuncParams[identifierParam].add(paramValue)) {
                emit FuncParamAdded(_contract, func, paramOffset, paramValue, msg.sender);
                emit FuncSigParamAdded(_contract, funcSig, paramOffset, paramValue, msg.sender);
            }
        }

        bytes32 identifier = _getIdentifier(_contract, funcSig);
        confinedFuncParamOffsets[identifier].add(paramOffset);
    }

    function addFuncSigParams(address _contract, bytes4 funcSig, uint256 paramOffset, bytes32[] calldata paramValueList) public onlyOwner {
        if (paramValueList.length == 0) revert EmptyList("Empty ParamValueList");

        // Cannot configure function parameter authorization without function authorization configured
        if (!_isAllowedSelector(_contract, funcSig)) revert FuncAuthNotConfigured(_contract, funcSig);

        bytes32 identifierParam = _getIdentifierParams(_contract, funcSig, paramOffset);
        for (uint256 index = 0; index < paramValueList.length; index++) {
            bytes32 paramValue = paramValueList[index];
            if (allowedFuncParams[identifierParam].add(paramValue)) {
                emit FuncSigParamAdded(_contract, funcSig, paramOffset, paramValue, msg.sender);
            }
        }

        bytes32 identifier = _getIdentifier(_contract, funcSig);
        confinedFuncParamOffsets[identifier].add(paramOffset);
    }

    function removeFuncParams(
        address _contract,
        string calldata func,
        uint256 paramOffset,
        bytes32[] calldata paramValueList
    ) external onlyOwner {
        bytes4 funcSig = bytes4(keccak256(bytes(func)));
        if (paramValueList.length == 0) revert EmptyList("Empty ParamValueList");

        bytes32 identifierParam = _getIdentifierParams(_contract, funcSig, paramOffset);

        for (uint256 index = 0; index < paramValueList.length; index++) {
            bytes32 paramValue = paramValueList[index];
            if (allowedFuncParams[identifierParam].remove(paramValue)) {
                emit FuncParamRemoved(_contract, func, paramOffset, paramValue, msg.sender);
                emit FuncSigParamRemoved(_contract, funcSig, paramOffset, paramValue, msg.sender);
            }
        }

        if (allowedFuncParams[identifierParam].length() == 0) {
            bytes32 identifier = _getIdentifier(_contract, funcSig);
            confinedFuncParamOffsets[identifier].remove(paramOffset);
        }
    }

    function removeFuncSigParams(
        address _contract,
        bytes4 funcSig,
        uint256 paramOffset,
        bytes32[] calldata paramValueList
    ) public onlyOwner {
        if (paramValueList.length == 0) revert EmptyList("Empty ParamValueList");

        bytes32 identifierParam = _getIdentifierParams(_contract, funcSig, paramOffset);

        for (uint256 index = 0; index < paramValueList.length; index++) {
            bytes32 paramValue = paramValueList[index];
            if (allowedFuncParams[identifierParam].remove(paramValue)) {
                emit FuncSigParamRemoved(_contract, funcSig, paramOffset, paramValue, msg.sender);
            }
        }

        if (allowedFuncParams[identifierParam].length() == 0) {
            bytes32 identifier = _getIdentifier(_contract, funcSig);
            confinedFuncParamOffsets[identifier].remove(paramOffset);
        }
    }
}
