// SPDX-License-Identifier: WTFPL.ETH
pragma solidity ^0.8.15;

import "forge-std/Test.sol";
import "src/Resolver.sol";

/**
 * @author 0xc0de4c0ffee, sshmatrix
 * @title CCIP2.ETH Resolver tester
 */
contract ResolverGoerli is Test {
    error OffchainLookup(address sender, string[] urls, bytes callData, bytes4 callbackFunction, bytes extraData);

    Resolver public CCIP2;
    iENS public ENS;

    /// @dev : setup
    function setUp() public {
        CCIP2 = new Resolver();
    }

    /// @dev : DNS Decoder
    function DNSDecode(bytes calldata encoded) public pure returns (string memory _name, bytes32 namehash) {
        uint256 j;
        uint256 len;
        bytes[] memory labels = new bytes[](12); // max 11 ...bob.alice.istest.eth
        for (uint256 i; encoded[i] > 0x0;) {
            len = uint8(bytes1(encoded[i:++i]));
            labels[j] = encoded[i:i += len];
            j++;
        }
        _name = string(labels[--j]); // 'eth' label
        // pop 'istest' label
        namehash = keccak256(abi.encodePacked(bytes32(0), keccak256(labels[j--]))); // namehash of 'eth'
        if (j == 0) {
            // istest.eth
            return (
                string.concat(string(labels[0]), ".", _name),
                keccak256(abi.encodePacked(namehash, keccak256(labels[0])))
            );
        }

        while (j > 0) {
            // return ...bob.alice.eth
            _name = string.concat(string(labels[--j]), ".", _name); // pop 'istest' label
            namehash = keccak256(abi.encodePacked(namehash, keccak256(labels[j]))); // namehash without 'istest' label
        }
    }

    /// @dev : DNS Encoder
    function DNSEncode(bytes memory _domain) internal pure returns (bytes memory _name, bytes32 _namehash) {
        uint256 i = _domain.length;
        _name = abi.encodePacked(bytes1(0));
        bytes memory _label;
        _namehash = bytes32(0);
        unchecked {
            while (i > 0) {
                --i;
                if (_domain[i] == bytes1(".")) {
                    _name = bytes.concat(bytes1(uint8(_label.length)), _label, _name);
                    _namehash = keccak256(abi.encodePacked(_namehash, keccak256(_label)));
                    _label = "";
                } else {
                    _label = bytes.concat(_domain[i], _label);
                }
            }
            _name = bytes.concat(bytes1(uint8(_label.length)), _label, _name);
            _namehash = keccak256(abi.encodePacked(_namehash, keccak256(_label)));
        }
    }

    /// @dev : get some values
    function testConstants() public view {
        bytes memory _src = "vitalik.eth";
        (bytes memory _name,) = DNSEncode(_src);
        console.logBytes(_name);
        bytes memory _test = "vitalik.ccip2.eth";
        (, bytes32 _namehash) = DNSEncode(_test);
        console.logBytes32(_namehash);
        console.logBytes4(CCIP2.resolve.selector);
    }

    /// @dev : test CCIP-Read call
    function testCCIPRevert() public {}

    /// @dev : test full end-to-end CCIP2
    function testCCIPCallback() public {}
}
