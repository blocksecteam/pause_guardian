// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/proxy/Clones.sol";

import "./PauseModule.sol";

contract PauseModuleFactory is Ownable {
    bytes32 public constant NAME = "PauseModuleFactory";
    uint256 public constant VERSION = 1;

    /// @notice The latest implementation contract
    address public latestImplementation;

    /// @notice all added implemantion contracts
    address[] public implementations;

    /// @notice record deployment history
    /// @dev deployer => proxy contract list
    mapping(address => address[]) public records;

    /// Event
    event ProxyCreated(address indexed deployer, address indexed implementation, address indexed proxy);
    event ImplementationAdded(address indexed implementation);

    /// Error
    error NoImplementation();
    error InvalidRange(uint256 start, uint256 end);

    constructor(address owner) {
        _transferOwnership(owner);
    }

    /// View functions
    function getAllImplementations() external view returns (address[] memory impls) {
        impls = implementations;
    }

    function getAllRecords(address deployer) external view returns (address[] memory proxies) {
        return records[deployer];
    }

    function getRecords(address deployer, uint256 start, uint256 end) external view returns (address[] memory proxies) {
        address[] storage record = records[deployer];
        uint256 size = record.length;
        if (end > size) end = size;
        if (end <= start) revert InvalidRange(start, end);

        proxies = new address[](end - start);
        for (uint256 i = start; i < end; i++) {
            proxies[i - start] = record[i];
        }
    }

    function getCreate2Address(address creator, bytes32 salt) external view returns (address instance) {
        address implementation = latestImplementation;
        if (implementation == address(0)) return address(0);
        salt = keccak256(abi.encode(creator, salt));
        return Clones.predictDeterministicAddress(implementation, salt);
    }

    /// External functions

    /// @dev Create EIP 1167 proxy with create2
    function create2(bytes32 salt) public returns (address instance) {
        if (latestImplementation == address(0)) revert NoImplementation();

        // Add msg.sender to the salt so no address collissions will occur between different users.
        salt = keccak256(abi.encode(msg.sender, salt));
        instance = Clones.cloneDeterministic(latestImplementation, salt);
        emit ProxyCreated(msg.sender, latestImplementation, instance);
    }

    /// @notice Create and record the creation in the contract
    function create2AndRecord(bytes32 salt) public returns (address instance) {
        instance = create2(salt);
        records[msg.sender].push(instance);
    }

    /// @notice Register a implementation contract of Pause module to the factory. Only the owner is allowed
    function addImplementation(address impl) external onlyOwner {
        latestImplementation = impl;
        implementations.push(impl);
        emit ImplementationAdded(impl);
    }
}
