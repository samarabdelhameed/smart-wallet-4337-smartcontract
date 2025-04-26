// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {P256} from "./P256.sol";
import {Base64URL} from "./utils/Base64URL.sol";
import "forge-std/console2.sol";

/**
 * @title WebAuthn
 * @notice Helper library for external contracts to verify WebAuthn signatures.
 */
library WebAuthn {
    bytes1 constant AUTH_DATA_FLAGS_UP = 0x01; // Bit 0
    bytes1 constant AUTH_DATA_FLAGS_UV = 0x04; // Bit 2
    bytes1 constant AUTH_DATA_FLAGS_BE = 0x08; // Bit 3
    bytes1 constant AUTH_DATA_FLAGS_BS = 0x10; // Bit 4

    /// @notice Checks whether `substr` occurs in `str` starting at a given byte offset.
    function contains(
        string memory substr,
        string memory str,
        uint256 location
    ) internal pure returns (bool) {
        bytes memory substrBytes = bytes(substr);
        bytes memory strBytes = bytes(str);

        uint256 substrLen = substrBytes.length;
        uint256 strLen = strBytes.length;

        for (uint256 i = 0; i < substrLen; i++) {
            if (location + i >= strLen) {
                return false;
            }

            if (substrBytes[i] != strBytes[location + i]) {
                return false;
            }
        }

        return true;
    }

    /// @notice Verifies the authFlags in authenticatorData.
    function checkAuthFlags(
        bytes1 flags,
        bool requireUserVerification
    ) internal pure returns (bool) {
        // 17. Verify that the UP bit of the flags in authData is set.
        if (flags & AUTH_DATA_FLAGS_UP != AUTH_DATA_FLAGS_UP) {
            return false;
        }

        // 18. If user verification was determined to be required, verify that the UV bit of the flags in authData is set.
        if (
            requireUserVerification &&
            (flags & AUTH_DATA_FLAGS_UV) != AUTH_DATA_FLAGS_UV
        ) {
            return false;
        }

        // 19. If the BE bit of the flags in authData is not set, verify that the BS bit is not set.
        if (flags & AUTH_DATA_FLAGS_BE != AUTH_DATA_FLAGS_BE) {
            if (flags & AUTH_DATA_FLAGS_BS == AUTH_DATA_FLAGS_BS) {
                return false;
            }
        }

        return true;
    }

    /// @notice Verifies a WebAuthn P256 signature (Authentication Assertion).
    function verifySignature(
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
    ) internal view returns (bool) {
        // Check that authenticatorData has good flags
        if (
            authenticatorData.length < 32 ||
            !checkAuthFlags(authenticatorData[32], requireUserVerification)
        ) {
            return false;
        }

        // Check that response is for an authentication assertion
        string memory responseType = '"type":"webauthn.get"';
        if (!contains(responseType, clientDataJSON, responseTypeLocation)) {
            return false;
        }

        // Check that challenge is in the clientDataJSON
        string memory challengeB64url = Base64URL.encode(challenge);
        string memory challengeProperty = string.concat(
            '"challenge":"',
            challengeB64url,
            '"'
        );

        if (!contains(challengeProperty, clientDataJSON, challengeLocation)) {
            return false;
        }

        // Check that the public key signed sha256(authenticatorData || sha256(clientDataJSON))
        bytes32 clientDataJSONHash = sha256(bytes(clientDataJSON));
        bytes32 messageHash = sha256(
            abi.encodePacked(authenticatorData, clientDataJSONHash)
        );

        // Check that the signature is valid while allowing malleability
        return P256.verifySignatureAllowMalleability(messageHash, r, s, x, y);
    }
}
