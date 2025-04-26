// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

library P256 {
    function verifySignatureAllowMalleability(
        bytes32 messageHash,
        uint256 r,
        uint256 s,
        uint256 x,
        uint256 y
    ) internal pure returns (bool) {
        // Dummy implementation: always return false
        // هنعدلها بعدين لو حبينا نربطها بليبرري جاهزة
        return false;
    }
}
