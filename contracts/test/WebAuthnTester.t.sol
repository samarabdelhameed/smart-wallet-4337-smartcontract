// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import "forge-std/Test.sol";
import "../src/WebAuthnTester.sol";

contract WebAuthnTesterTest is Test {
    WebAuthnTester tester;

    function setUp() public {
        tester = new WebAuthnTester();
    }

    function testDummyVerifySignature() public {
        bytes memory challenge = "";
        bytes memory authenticatorData = hex"00";
        bool requireUserVerification = false;
        string memory clientDataJSON = "";
        uint256 challengeLocation = 0;
        uint256 responseTypeLocation = 0;
        uint256 r = 0;
        uint256 s = 0;
        uint256 x = 0;
        uint256 y = 0;

        bool success = tester.testVerifySignature(
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

        assertTrue(!success, "Expected the dummy verification to fail");
    }
}
