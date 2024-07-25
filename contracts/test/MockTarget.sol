// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import "hardhat/console.sol";

contract MockTarget is ERC20, Ownable {

    string public note = "init note";

    address public A = address(0);
    address public B = address(0);

    address public paramAuthTargetAddress = address(1);
    int public paramAuthTargetInt = int(1);
    uint public paramAuthTargetUint = uint(1);
    bool public paramAuthTargetBool = true;

    // no restriction
    bytes public paramAuthTargetBytes = hex'deadbeef';
    int[2][3] public paramAuthTargetIntArray_3_2;
    uint[][4] public paramAuthTargetUintDynArray_D_4;

    event noteChanged(string indexed oldNote, string indexed newNote);
    event forbiddenNoteChanged(string indexed oldNote, string indexed newNote);

    event AChanged(address indexed oldA, address indexed newA);
    event BChanged(address indexed oldB, address indexed newB);
    event dummyString(string indexed s);

    constructor(address owner) ERC20("Mock Target", "MT"){
        _transferOwnership(owner);
    }

    function changeNote(string calldata newNote) onlyOwner public {
        string memory oldNote = note;
        note = newNote;

        emit noteChanged(oldNote, newNote);
    }

    function changeNoteForbidden(string calldata newNote) onlyOwner public {
        string memory oldNote = note;
        note = newNote;

        emit forbiddenNoteChanged(oldNote, newNote);
    }

    function paramAuthA(address a, address d1, bool d2, int8 d3, string calldata dummy) onlyOwner public {
        address oldA = A;
        A = a;

        d1;
        d2;
        d3;

        emit AChanged(oldA, A);
        emit dummyString(dummy);
    }

    function paramAuthB(address b, address d1, bool d2, int8 d3, string calldata dummy) onlyOwner public {
        address oldB = B;
        B = b;

        d1;
        d2;
        d3;

        emit BChanged(oldB, B);
        emit dummyString(dummy);
    }

    function paramAuthC(address b, bytes calldata d1, bool d2, uint8 d3, string calldata dummy) onlyOwner public {
        address oldB = B;
        B = b;

        d1;
        d2;
        d3;

        emit BChanged(oldB, B);
        emit dummyString(dummy);
    }

    function checkIntArray_3_2(int[2][3] calldata input) public view returns (bool) {
        for (uint i = 0; i < 3; i++)
            for (uint j = 0; j < 2; j++)
                if (input[i][j] != paramAuthTargetIntArray_3_2[i][j])
                    return false;
        return true;
    }

    function checkUintDynArray_D_4(uint [][4] calldata input) public view returns (bool) {

        for (uint i = 0; i < 4; i++) {
            if (input[i].length != paramAuthTargetUintDynArray_D_4[i].length) {
                return false;
            }
            for (uint j = 0; j < input[i].length; j++) {
                if (input[i][j] != paramAuthTargetUintDynArray_D_4[i][j]) {
                    return false;
                }
            }
        }

        return true;
    }

    function paramAuthTarget(address a, bytes calldata b, bool c, int[2][3] calldata d, int e, uint[][4] memory f, uint g) onlyOwner public {
        paramAuthTargetAddress = a;
        paramAuthTargetBool = c;
        paramAuthTargetInt = e;
        paramAuthTargetUint = g;

        paramAuthTargetBytes = b;
        paramAuthTargetIntArray_3_2 = d;
        paramAuthTargetUintDynArray_D_4 = f;
    }
}