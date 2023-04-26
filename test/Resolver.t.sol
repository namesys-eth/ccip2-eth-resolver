// SPDX-License-Identifier: WTFPL.ETH
pragma solidity ^0.8.15;

import "forge-std/Test.sol";
import "src/Resolver.sol";
import {Surl} from "surl/src/Surl.sol";
import "./Utils.sol";
/**
 * @author 0xc0de4c0ffee, sshmatrix
 * @title CCIP2.eth Resolver tester
 */

contract ResolverGoerli is Test {
    error OffchainLookup(address sender, string[] urls, bytes callData, bytes4 callbackFunction, bytes extraData);

    Resolver public resolver;
    xENS public ENS = xENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);

    Utils public utils = new Utils();
    /// @dev : setup

    function setUp() public {
        resolver = new Resolver();
        //(uint256 status, bytes memory data) = "https://httpbin.org/get".get();
    }

    using Surl for *;

    /// @dev : get some values
    function testSanityUtils() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "virgil";
        _name[1] = "eth";
        (bytes32 _namehash, bytes memory _encoded) = utils.Encode(_name);
        (string memory _path, string memory _domain) = Utils(address(utils)).Format(_encoded);
        assertEq(_encoded, bytes.concat(bytes1(uint8(6)), "virgil", bytes1(uint8(3)), "eth", bytes1(0)));
        assertEq(_namehash, bytes32(0x2abe74dc42b79fff0accc104dbf6ef6f150d5eb4ba14cdae4a404eb7890d2e19));
        assertEq(_path, string("eth/virgil"));
        assertEq(_domain, string("virgil.eth"));
    }

    /// @dev : test CCIP-Read call
    function testResolve1() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "ccip2";
        _name[1] = "eth";
        (bytes32 _namehash, bytes memory _encoded) = utils.Encode(_name);
        address _addr = ENS.owner(_namehash);
        console.logAddress(_addr);
        vm.prank(_addr);
        ENS.setOwner(_namehash, address(this));
        resolver.setContenthash(
            _namehash, hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c"
        );
        console.logAddress(ENS.owner(_namehash));
        (string memory _path, string memory _domain) = Utils(address(utils)).Format(_encoded);
        bytes memory _request = abi.encodeWithSelector(iResolver.addr.selector, _namehash);
        resolver.resolve(_encoded, _request);
    }

    /// @dev : test full end-to-end resolver
    function testCCIPCallback() public {}
}
