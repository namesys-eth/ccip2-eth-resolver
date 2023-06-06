// SPDX-License-Identifier: WTFPL.ETH
pragma solidity ^0.8.15;

import "forge-std/Test.sol";
import "src/GatewayManager.sol";
/**
 * @author freetib.eth, sshmatrix.eth
 * @title CCIP2.eth Resolver tester
 */

interface xENS is iENS {
    function setResolver(bytes32 node, address resolver) external;
    function setOwner(bytes32 node, address owner) external;
}

contract GatewayManagerTest is Test {
    GatewayManager public gateway;
    Utils public utils = new Utils();

    function setUp() public {
        //gateway = new GatewayManager();
    }

    xENS public ENS = xENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);

    function testStatic() public view {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "freetibet";
        _name[1] = "eth";
        (bytes32 _namehash, bytes memory _encoded) = utils.Encode(_name);
        bytes memory _request = abi.encodePacked(iResolver.contenthash.selector, _namehash);
        console.logBytes(_request);
        _request = abi.encodeWithSelector(iResolver.contenthash.selector, _namehash);
        console.logBytes(_request);
        if (ENS.recordExists(_namehash)) {
            address _resolver = ENS.resolver(_namehash);
            //if (iERC165(_resolver).supportsInterface(iENSIP10.resolve.selector)) {
            //    return iENSIP10(_resolver).resolve(name, data);
            //} else
            if (iERC165(_resolver).supportsInterface(iResolver.contenthash.selector)) {
                (bool ok, bytes memory result) = _resolver.staticcall(_request);
                if (ok && result.length > 0) {
                    console.logBytes(abi.encode(result));
                    console.logBytes(result);
                } else {
                    console.logBytes(abi.encode(result));
                    console.logBytes(result);
                }
            }
        } else {
            revert("INVALID_DAPP_SERVICE");
        }
    }
}
// 0xbc1c58d182b6f6c910a7648fa810793ffa417452de9de0db373b3039457e85b110eced31

contract Utils {
    function Format(bytes calldata _encoded) external pure returns (string memory _path, string memory _domain) {
        uint256 n = 1;
        uint256 len = uint8(bytes1(_encoded[:1]));
        bytes memory _label;
        _label = _encoded[1:n += len];
        _path = string(_label);
        _domain = _path;
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

    function chunk(bytes calldata _b, uint256 _start, uint256 _end) external pure returns (bytes memory) {
        return _b[_start:_end == 0 ? _b.length : _end];
    }
}
