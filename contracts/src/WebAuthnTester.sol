// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {WebAuthn} from "./WebAuthn.sol";

contract WebAuthnTester {
    function testVerifySignature(
        bytes memory challenge,
        bytes memory authenticatorData,
        bool requireUserVerification,
        string memory clientDataJSON,
        uint256 challengeLocation,
        uint256 responseTypeLocation,
        uint256 r,
        uint256 s,
        uint256 x,
        uint256 y
    ) external view returns (bool) {
        return
            WebAuthn.verifySignature(
                challenge,
                authenticatorData,
                requireUserVerification,
                clientDataJSON,
                challengeLocation,
                responseTypeLocation,
                r,
                s,
                x,
                y
            );
    }
}
