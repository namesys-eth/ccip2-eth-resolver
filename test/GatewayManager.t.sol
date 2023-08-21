// SPDX-License-Identifier: WTFPL.ETH
pragma solidity ^0.8.15;

import "forge-std/Test.sol";
import "src/GatewayManager.sol";

interface xENS is iENS {
    function setResolver(bytes32 node, address resolver) external;
    function setOwner(bytes32 node, address owner) external;
}

/**
 * @author freetib.eth, sshmatrix.eth
 * @title CCIP2.eth Gatewat tester
 */
contract GatewayManagerTest is Test {
    GatewayManager public gateway;
    Utils public utils = new Utils();

    function setUp() public {
        gateway = new GatewayManager();
    }

    xENS public ENS = xENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);

    /// @dev Test Web2 gateway as recordhash
    function test1_Web2Support() public {
        assertTrue(gateway.isWeb2(abi.encodePacked("https://ccip.namesys.xyz")));
        assertEq(
            gateway.randomGateways(
                abi.encodePacked("https://ccip.namesys.xyz"), string("/.well-known/eth/freetibet/text/avatar"), 0
            )[0],
            string("https://ccip.namesys.xyz/.well-known/eth/freetibet/text/avatar.json?t={data}")
        );
    }

    /// @dev Test record path mappings
    function test2_FunctionMap() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "virgil";
        _name[1] = "eth";
        (bytes32 _namehash, bytes memory _fullname) = utils.Encode(_name);
        bytes memory request = abi.encodeWithSelector(iResolver.contenthash.selector, _namehash);
        assertEq(gateway.funcToJson(request), "contenthash");
        request = abi.encodeWithSelector(iResolver.addr.selector, _namehash);
        assertEq(gateway.funcToJson(request), "address/60");
        request = abi.encodeWithSelector(iResolver.text.selector, _namehash, "avatar");
        assertEq(gateway.funcToJson(request), "text/avatar");
        request = abi.encodeWithSelector(iOverloadResolver.addr.selector, _namehash, 1337);
        assertEq(gateway.funcToJson(request), "address/1337");
        request = abi.encodeWithSelector(iResolver.interfaceImplementer.selector, _namehash, bytes4(0xffffffff));
        assertEq(gateway.funcToJson(request), "interface/0xffffffff");
        request = abi.encodeWithSelector(iResolver.dnsRecord.selector, _namehash, _namehash, uint16(42));
        assertEq(gateway.funcToJson(request), "dns/42");
        request = abi.encodeWithSelector(iOverloadResolver.dnsRecord.selector, _namehash, _fullname, uint16(42));
        assertEq(gateway.funcToJson(request), "dns/42");
    }

    /// @dev Test address checksum
    function test3_ChecksumAddress() public {
        string memory addrStr = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e";
        address addr = address(bytes20(hex"00000000000c2e074ec69a0dfb2997ba6c7d2e1e"));
        assertEq(gateway.toChecksumAddress(addr), addrStr);

        addrStr = "0xc0dE4C0FfEEc0de4c0fFeeC0DE4C0ffeEC0DE402";
        addr = address(bytes20(hex"c0de4c0ffeec0de4c0ffeec0de4c0ffeec0de402"));
        assertEq(gateway.toChecksumAddress(addr), addrStr);

        addrStr = "0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF";
        addr = address(bytes20(hex"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));
        assertEq(gateway.toChecksumAddress(addr), addrStr);

        addrStr = "0x0000000000000000000000000000000000000000";
        addr = address(bytes20(hex"0000000000000000000000000000000000000000"));
        assertEq(gateway.toChecksumAddress(addr), addrStr);
    }

    /// @dev Test uint to string conversion
    function test4_UintToString() public {
        uint256 n = 1234567890;
        string memory k = "1234567890";
        assertEq(gateway.uintToString(n), k);
        n = 99999999999999999999;
        k = "99999999999999999999";
        assertEq(gateway.uintToString(n), k);
        n = 11223344556677889900;
        k = "11223344556677889900";
        assertEq(gateway.uintToString(n), k);
        n = 42;
        k = "42";
        assertEq(gateway.uintToString(n), k);
        n = 0;
        k = "0";
        assertEq(gateway.uintToString(n), k);
        n = type(uint256).max;
        k = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assertEq(gateway.uintToString(n), k);
    }

    /// @dev Test bytes to hex string conversion
    function test5_bytesToHexString() public {
        string memory bStr = "e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        bytes memory bBytes = hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        assertEq(bStr, gateway.bytesToHexString(bBytes, 0));

        bStr = "bc1c58d182b6f6c910a7648fa810793ffa417452de9de0db373b3039457e85b110eced31";
        bBytes = hex"bc1c58d182b6f6c910a7648fa810793ffa417452de9de0db373b3039457e85b110eced31";
        assertEq(bStr, gateway.bytesToHexString(bBytes, 0));

        bStr = "00000000000000000000";
        bBytes = hex"00000000000000000000";
        assertEq(bStr, gateway.bytesToHexString(bBytes, 0));

        bStr = "ffffffffffffffffffffffffffffff";
        bBytes = hex"ffffffffffffffffffffffffffffff";
        assertEq(bStr, gateway.bytesToHexString(bBytes, 0));

        bStr = "ffffffffffffffffffffffffffffff";
        bBytes = hex"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        assertEq(bStr, gateway.bytesToHexString(bBytes, 0));
    }

    /// @dev Test web2 gateways
    function test6_Web2Gateways() public {
        string[] memory gateways = gateway.listWeb2Gateways();
        assertEq("ccip.namesys.xyz", gateways[0]);
        assertEq(1, gateways.length);

        vm.expectRevert(abi.encodeWithSelector(GatewayManager.InvalidRequest.selector, "LAST_GATEWAY"));
        gateway.removeWeb2Gateway(0);

        gateway.addWeb2Gateway("ccip2.namesys.xyz");
        gateways = gateway.listWeb2Gateways();
        assertEq("ccip.namesys.xyz", gateways[0]);
        assertEq("ccip2.namesys.xyz", gateways[1]);
        assertEq(2, gateways.length);

        gateway.replaceWeb2Gateway(1, "ccipx.namesys.xyz");
        gateways = gateway.listWeb2Gateways();
        assertEq("ccip.namesys.xyz", gateways[0]);
        assertEq("ccipx.namesys.xyz", gateways[1]);
        assertEq(2, gateways.length);

        gateway.removeWeb2Gateway(0);
        gateways = gateway.listWeb2Gateways();
        assertEq("ccipx.namesys.xyz", gateways[0]);
        assertEq(1, gateways.length);

        gateway.addWeb2Gateway("ccip2.namesys.xyz");
        gateway.replaceWeb2Gateway(0, "ccip.namesys.xyz");
        gateway.removeWeb2Gateway(1);
        gateways = gateway.listWeb2Gateways();
        assertEq("ccip.namesys.xyz", gateways[0]);
        assertEq(1, gateways.length);
    }

    /// @dev Test web3 gateways
    function test7_Web3Gateways() public {
        string[] memory gateways = gateway.listWeb3Gateways();
        assertEq("dweb.link", gateways[0]);
        assertEq("ipfs.io", gateways[1]);
        assertEq(2, gateways.length);

        gateway.removeWeb3Gateway(0);
        vm.expectRevert(abi.encodeWithSelector(GatewayManager.InvalidRequest.selector, "LAST_GATEWAY"));
        gateway.removeWeb3Gateway(0);

        gateway.addWeb3Gateway("dweb.link");
        gateways = gateway.listWeb3Gateways();
        assertEq("dweb.link", gateways[1]);
        assertEq("ipfs.io", gateways[0]);
        assertEq(2, gateways.length);

        gateway.replaceWeb3Gateway(0, "ipfs.namesys.xyz");
        gateways = gateway.listWeb3Gateways();
        assertEq("dweb.link", gateways[1]);
        assertEq("ipfs.namesys.xyz", gateways[0]);
        assertEq(2, gateways.length);

        gateway.removeWeb3Gateway(0);
        gateways = gateway.listWeb3Gateways();
        assertEq("dweb.link", gateways[0]);
        assertEq(1, gateways.length);

        gateway.addWeb3Gateway("ipfs.namesys.xyz");
        gateway.replaceWeb3Gateway(0, "ipfs.io");
        gateway.removeWeb3Gateway(0);
        gateways = gateway.listWeb3Gateways();
        assertEq("ipfs.namesys.xyz", gateways[0]);
        assertEq(1, gateways.length);
    }

    /// @dev Test a gateway
    function test8_RandomGateway() public {
        string memory _path = "/.well-known/eth/freetib/contenthash";
        bytes memory _recordhash;
        string[] memory gateways = gateway.randomGateways(_recordhash, _path, 0);
        assertEq(gateways[0], "https://ccip.namesys.xyz/.well-known/eth/freetib/contenthash.json?t={data}");
        assertEq(1, gateways.length);
        gateway.addWeb2Gateway("ccip2.namesys.xyz");
        gateways = gateway.randomGateways(_recordhash, _path, 0);
        assertEq(2, gateways.length);
        assertEq(gateways[0], "https://ccip.namesys.xyz/.well-known/eth/freetib/contenthash.json?t={data}");
        assertEq(gateways[1], "https://ccip2.namesys.xyz/.well-known/eth/freetib/contenthash.json?t={data}");

        _recordhash = bytes("https://ccip.namesys.xyz");
        gateways = gateway.randomGateways(_recordhash, _path, 0);
        assertEq(1, gateways.length);
        assertEq(gateways[0], "https://ccip.namesys.xyz/.well-known/eth/freetib/contenthash.json?t={data}");

        gateway.addWeb3Gateway("ipfs.namesys.xyz");
        gateway.addWeb3Gateway("ipfs2.namesys.xyz");
        _recordhash = hex"3c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        gateways = gateway.randomGateways(_recordhash, _path, 0);
        assertEq(4, gateways.length);
        assertEq(
            gateways[0],
            "https://e5010172002408011220.3c5aba6c9b5055a5fa12281c486188ed.8ae2b6ef394b3d981b00d17a4b51735c.ipfs2.eth.limo/.well-known/eth/freetib/contenthash.json?t={data}"
        );
        assertEq(
            gateways[1],
            "https://dweb.link/ipns/f01720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c/.well-known/eth/freetib/contenthash.json?t={data}"
        );
        assertEq(
            gateways[2],
            "https://ipfs.namesys.xyz/ipns/f01720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c/.well-known/eth/freetib/contenthash.json?t={data}"
        );
        assertEq(
            gateways[3],
            "https://ccip.namesys.xyz/ipns/f01720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c/.well-known/eth/freetib/contenthash.json?t={data}"
        );

        _recordhash = hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        gateways = gateway.randomGateways(_recordhash, _path, 0);
        assertEq(4, gateways.length);
        assertEq(
            gateways[0],
            "https://e5010172002408011220.3c5aba6c9b5055a5fa12281c486188ed.8ae2b6ef394b3d981b00d17a4b51735c.ipfs2.eth.limo/.well-known/eth/freetib/contenthash.json?t={data}"
        );
        assertEq(
            gateways[1],
            "https://dweb.link/ipns/f01720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c/.well-known/eth/freetib/contenthash.json?t={data}"
        );
        assertEq(
            gateways[2],
            "https://ipfs.namesys.xyz/ipns/f01720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c/.well-known/eth/freetib/contenthash.json?t={data}"
        );
        assertEq(
            gateways[3],
            "https://ccip.namesys.xyz/ipns/f01720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c/.well-known/eth/freetib/contenthash.json?t={data}"
        );
    }
}

/// @dev Utility functions
contract Utils {
    function Format(bytes calldata _encoded) external pure returns (string memory _path, string memory _domain) {
        uint256 n = 1;
        uint256 len = uint8(bytes1(_encoded[0]));
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
