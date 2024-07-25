// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.17;

import "./PauseModuleFactory.sol";
import "./PauseModule.sol";

contract PauseModuleHelper {
    bytes32 public constant NAME = "PauseModuleHelper";
    uint256 public constant VERSION = 1;

    event PauseModuleAdded(address indexed pauseModule, address indexed safe, address indexed factory);

    /// @notice deploy and register pause module for Safe
    /// @dev should be invoked by Safe via `delegatecall`
    function initPauseModule(PauseModuleFactory factory, bytes32 salt, address[] calldata delegates) external {
        address safe = address(this);

        PauseModule pauseModule = PauseModule(payable(factory.create2AndRecord(salt)));
        pauseModule.initialize(delegates, safe);

        // enable module in Safe
        IGnosisSafe(safe).enableModule(address(pauseModule));

        emit PauseModuleAdded(address(pauseModule), safe, address(factory));
    }
}
