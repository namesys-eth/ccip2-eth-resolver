// SPDX-License-Identifier: WTFPL.ETH
pragma solidity ^0.8.15;

import "forge-std/Test.sol";
import "src/CCIP2ETH.sol";
import "src/GatewayManager.sol";

/**
 * @author 0xc0de4c0ffee, sshmatrix
 * @title CCIP2.eth Resolver tester
 */

interface xENS is iENS {
    function setResolver(bytes32 node, address resolver) external;
    function setOwner(bytes32 node, address owner) external;
}

contract CCIP2ETHTest is Test {
    // using Surl for *;
    error OffchainLookup(address sender, string[] urls, bytes callData, bytes4 callbackFunction, bytes extraData);

    CCIP2ETH public ccip2eth;
    iGatewayManager public gateway;
    xENS public ENS = xENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);

    Utils public utils = new Utils();
    /// @dev : setup
    bytes32 dotETH = keccak256(abi.encodePacked(bytes32(0), keccak256("eth")));

    function setUp() public {
        gateway = new GatewayManager();
        ccip2eth = new CCIP2ETH(address(gateway));
    }

    /// @dev : get some values
    function testSanityUtils() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "virgil";
        _name[1] = "eth";
        (bytes32 _namehash, bytes memory _encoded) = utils.Encode(_name);
        (string memory _path, string memory _domain) = utils.Format(_encoded);
        assertEq(_encoded, bytes.concat(bytes1(uint8(6)), "virgil", bytes1(uint8(3)), "eth", bytes1(0)));
        assertEq(_namehash, keccak256(abi.encodePacked(dotETH, keccak256("virgil"))));
        assertEq(_path, string("eth/virgil"));
        assertEq(_domain, string("virgil.eth"));
    }

    /// @dev : test CCIP-Read call level 2
    function testResolveLevel2() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "ccip2";
        _name[1] = "eth";
        (bytes32 _namehash, bytes memory _encoded) = utils.Encode(_name);
        address _addr = ENS.owner(_namehash);
        vm.prank(_addr);
        ENS.setOwner(_namehash, address(this));
        ENS.setResolver(_namehash, address(ccip2eth));
        bytes memory _recordhash =
            hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        ccip2eth.setRecordhash(_namehash, _recordhash);
        (string memory _path, string memory _domain) = utils.Format(_encoded);
        bytes memory _request = abi.encodePacked(iResolver.addr.selector, _namehash);
        string memory _suffix = gateway.funcToJson(_request);
        bytes32 _checkHash = keccak256(
            abi.encodePacked(address(ccip2eth), blockhash(block.number - 1), address(this), _domain, _path, _suffix)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                iENSIP10.OffchainLookup.selector,
                address(ccip2eth),
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _suffix), uint256(_checkHash)
                ),
                abi.encodePacked(uint32(block.timestamp / 60) * 60),
                ccip2eth.__callback.selector,
                abi.encode(_namehash, address(this), block.number - 1, _namehash, _checkHash, _domain, _path, _suffix)
            )
        );
        ccip2eth.resolve(_encoded, _request);
    }
    /// @dev : test CCIP-Read call

    function testResolveLevel3() public {
        bytes[] memory _name = new bytes[](3);
        _name[0] = "blog";
        _name[1] = "vitalik";
        _name[2] = "eth";
        (bytes32 _namehash, bytes memory _encoded) = utils.Encode(_name);
        address _addr = ENS.owner(_namehash);
        vm.prank(_addr);
        ENS.setOwner(_namehash, address(this));
        bytes memory _recordhash =
            hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        ccip2eth.setRecordhash(_namehash, _recordhash);
        (string memory _path, string memory _domain) = utils.Format(_encoded);
        bytes memory _request = abi.encodePacked(iResolver.text.selector, _namehash, abi.encode(string("avatar")));
        string memory _suffix = gateway.funcToJson(_request);
        bytes32 _checkHash =
            keccak256(abi.encodePacked(address(ccip2eth), blockhash(block.number - 1), _domain, _path, _suffix));
        vm.expectRevert(
            abi.encodeWithSelector(
                iENSIP10.OffchainLookup.selector,
                address(ccip2eth),
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _suffix), uint256(_checkHash)
                ),
                abi.encodePacked(uint32(block.timestamp / 60) * 60),
                ccip2eth.__callback.selector,
                abi.encode(_namehash, block.number - 1, _checkHash, _domain, _path, _suffix)
            )
        );
        ccip2eth.resolve(_encoded, _request);
    }

    function testResolveLevel7() public {
        bytes[] memory _base = new bytes[](2);
        _base[0] = "domain";
        _base[1] = "eth";

        (bytes32 _baseNode, bytes memory _encoded) = utils.Encode(_base);
        address _addr = ENS.owner(_baseNode);
        vm.prank(_addr);
        ENS.setOwner(_baseNode, address(this)); // owner records at level 2 only
        bytes memory _recordhash =
            hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        ccip2eth.setRecordhash(_baseNode, _recordhash);

        bytes[] memory _name = new bytes[](7);
        _name[0] = "never";
        _name[1] = "gonna";
        _name[2] = "give";
        _name[3] = "you";
        _name[4] = "up";
        _name[5] = "domain";
        _name[6] = "eth";
        bytes32 _namehash; // full namehash
        (_namehash, _encoded) = utils.Encode(_name);
        (string memory _path, string memory _domain) = utils.Format(_encoded);
        bytes memory _request = abi.encodePacked(iResolver.text.selector, _namehash, abi.encode(string("showcase")));
        string memory _suffix = gateway.funcToJson(_request);
        bytes32 _checkHash =
            keccak256(abi.encodePacked(address(ccip2eth), blockhash(block.number - 1), _domain, _path, _suffix));
        vm.expectRevert(
            abi.encodeWithSelector(
                iENSIP10.OffchainLookup.selector,
                address(ccip2eth),
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _suffix), uint256(_checkHash)
                ),
                abi.encodePacked(uint32(block.timestamp / 60) * 60),
                ccip2eth.__callback.selector,
                abi.encode(_baseNode, block.number - 1, _checkHash, _domain, _path, _suffix)
            )
        );
        ccip2eth.resolve(_encoded, _request);
    }

    /// @dev : test full end-to-end ccip2eth
    function testCCIPCallbackLevel2() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "ccip2";
        _name[1] = "eth";
        (bytes32 _node, bytes memory _encoded) = utils.Encode(_name);
        address _owner = ENS.owner(_node);

        uint256 PrivateKey = 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc;
        address _signer = vm.addr(PrivateKey);
        vm.prank(_owner);
        ENS.setOwner(_node, address(this));
        ccip2eth.approve(_node, _signer, true);
        bytes memory _recordhash =
            hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        ccip2eth.setRecordhash(_node, _recordhash);

        (string memory _path, string memory _domain) = utils.Format(_encoded);
        bytes memory _request = abi.encodePacked(iResolver.addr.selector, _node);
        string memory _suffix = gateway.funcToJson(_request);
        bytes32 _checkHash =
            keccak256(abi.encodePacked(address(ccip2eth), blockhash(block.number - 1), _domain, _path, _suffix));
        bytes memory _extradata = abi.encode(_node, block.number - 1, _checkHash, _domain, _path, _suffix);
        vm.expectRevert(
            abi.encodeWithSelector(
                iENSIP10.OffchainLookup.selector,
                address(ccip2eth),
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _suffix), uint256(_checkHash)
                ),
                abi.encodePacked(uint32(block.timestamp / 60) * 60),
                ccip2eth.__callback.selector,
                _extradata
            )
        );
        ccip2eth.resolve(_encoded, _request);
        bytes memory _result = abi.encode(address(this));
        string memory _req = string.concat(
            "Requesting Signature To Update Off-Chain ENS Record\n",
            "\nENS Domain: ",
            _domain,
            "\nRecord Type: ",
            _suffix,
            "\nExtradata: 0x",
            gateway.bytesToHexString(abi.encodePacked(keccak256(_result)), 0),
            "\nSigned By: eip155:1:",
            gateway.toChecksumAddress(address(_signer))
        );
        bytes32 _digest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n", gateway.uintToString(bytes(_req).length), _req)
        );

        assertTrue(ccip2eth.approved(_node, _signer));
        assertTrue(ccip2eth.isApprovedFor(address(this), _node, _signer));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PrivateKey, _digest);
        bytes memory _signature = abi.encodePacked(r, s, v);
        bytes memory _response =
            abi.encodePacked(ccip2eth.recordhash.selector, abi.encode(_signer, _signature, _result));
        assertEq(_result, ccip2eth.__callback(_response, _extradata));
    }
}

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
