// SPDX-License-Identifier: WTFPL.ETH
pragma solidity ^0.8.15;

contract Utils {
    function Format(bytes calldata _encoded) external pure returns (string memory _path, string memory _domain) {
        uint256 n = 1; // counter
        uint256 len = uint8(bytes1(_encoded[:1])); // length of label
        bytes memory _label; // = new bytes[](42); // maximum *in theory* 42 levels of sub.sub...domain.eth
        _label = _encoded[1:n += len];
        _path = string(_label); //"sub"
        _domain = _path; // "sub"
        /// @dev DNSDecode()
        while (_encoded[n] > 0x0) {
            len = uint8(bytes1(_encoded[n:++n]));
            _label = _encoded[n:n += len];
            _domain = string.concat(_domain, ".", string(_label));
            _path = string.concat(string(_label), "/", _path);
        }
    }

    function Encode(bytes[] memory _names) public pure returns (bytes32 _namehash, bytes memory _name) {
        uint256 i = _names.length;
        _name = abi.encodePacked(bytes1(0));
        _namehash = bytes32(0);
        unchecked {
            while (i > 0) {
                --i;
                _name = bytes.concat(bytes1(uint8(_names[i].length)), _names[i], _name);
                _namehash = keccak256(abi.encodePacked(_namehash, keccak256(_names[i])));
            }
        }
    }
}
