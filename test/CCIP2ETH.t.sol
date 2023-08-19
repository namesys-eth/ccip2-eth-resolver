// SPDX-License-Identifier: WTFPL.ETH
pragma solidity ^0.8.15;

import "forge-std/Test.sol";
import "src/CCIP2ETH.sol";
import "src/GatewayManager.sol";

interface xENS is iENS {
    function setResolver(bytes32 node, address resolver) external;
    function setOwner(bytes32 node, address owner) external;
}

/**
 * @author freetib.eth, sshmatrix.eth
 * @title CCIP2.eth Resolver tester
 * Note Tests unwrapped/legacy domains
 */
contract CCIP2ETHTestLegacy is Test {
    error OffchainLookup(address sender, string[] urls, bytes callData, bytes4 callbackFunction, bytes extraData);

    address EOA = address(this);
    CCIP2ETH public ccip2eth;
    iGatewayManager public gateway;
    xENS public ENS = xENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);
    uint256 public PrivateKeyOwner = 0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd;
    uint256 public PrivateKeySigner = 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc;

    Utils public utils = new Utils();
    string chainID;

    /// @dev Setup
    bytes32 dotETH = keccak256(abi.encodePacked(bytes32(0), keccak256("eth")));

    function setUp() public {
        gateway = new GatewayManager();
        chainID = gateway.uintToString(block.chainid);
        ccip2eth = new CCIP2ETH(address(gateway));
    }

    /// @dev Console logs
    function test1_01_ConsoleLog() public view {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "virgil";
        _name[1] = "eth";
        (bytes32 _namehash, bytes memory _encoded) = utils.Encode(_name);
        address _addr = ENS.owner(_namehash);
        _addr;
        _encoded;
        //console.log(_addr);
    }

    /// @dev Get some values
    function test1_02_UtilsSetup() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "virgil";
        _name[1] = "eth";
        (bytes32 _namehash, bytes memory _encoded) = utils.Encode(_name);
        (string memory _path, string memory _domain) = utils.Format(_encoded);
        assertEq(_encoded, abi.encodePacked(uint8(6), "virgil", uint8(3), "eth", uint8(0)));
        assertEq(
            _namehash,
            keccak256(abi.encodePacked(keccak256(abi.encodePacked(bytes32(0), keccak256("eth"))), keccak256("virgil")))
        );
        assertEq(_path, string("eth/virgil"));
        assertEq(_domain, string("virgil.eth"));
    }

    /// @dev Test CCIP-Read call for a domain
    function test1_03_ResolveLevel2() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "00081";
        _name[1] = "eth";
        (bytes32 _namehash, bytes memory _encoded) = utils.Encode(_name);
        address _addr = ENS.owner(_namehash);
        bytes memory _recordhash =
            hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        vm.prank(_addr);
        ccip2eth.setRecordhash(_namehash, _recordhash);
        (string memory _path, string memory _domain) = utils.Format(_encoded);
        bytes memory _request = abi.encodeWithSelector(iResolver.addr.selector, _namehash);
        string memory _recType = gateway.funcToJson(_request);
        bytes32 _checkhash = keccak256(
            abi.encodePacked(address(ccip2eth), blockhash(block.number - 1), _addr, _domain, _recType, _request)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                iENSIP10.OffchainLookup.selector,
                address(ccip2eth),
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _recType), uint256(_checkhash)
                ),
                abi.encodePacked(uint16(block.timestamp / 60)),
                ccip2eth.__callback.selector,
                abi.encode(_namehash, block.number - 1, _checkhash, _domain, _recType, _path, _encoded, _request)
            )
        );
        ccip2eth.resolve(_encoded, _request);
    }

    /// @dev Test subdomain-level CCIP-Read call
    function test1_04_ResolveLevel3() public {
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
        bytes memory _request = abi.encodeWithSelector(iResolver.text.selector, _namehash, abi.encode(string("avatar")));
        string memory _recType = gateway.funcToJson(_request);
        bytes32 _checkhash = keccak256(
            abi.encodePacked(address(ccip2eth), blockhash(block.number - 1), address(this), _domain, _recType, _request)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                iENSIP10.OffchainLookup.selector,
                address(ccip2eth),
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _recType), uint256(_checkhash)
                ),
                abi.encodePacked(uint16(block.timestamp / 60)),
                ccip2eth.__callback.selector,
                abi.encode(_namehash, block.number - 1, _checkhash, _domain, _recType, _path, _encoded, _request)
            )
        );
        ccip2eth.resolve(_encoded, _request);
    }

    /// @dev Test deep CCIP-Read call
    function test1_05_ResolveLevel7() public {
        bytes[] memory _base = new bytes[](2);
        _base[0] = "vitalik";
        _base[1] = "eth";
        (bytes32 _baseNode, bytes memory _encoded) = utils.Encode(_base);
        address _addr = ENS.owner(_baseNode);
        vm.prank(_addr);
        ENS.setOwner(_baseNode, address(this)); // Owner records set at level 2 only
        bytes memory _recordhash =
            hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        ccip2eth.setRecordhash(_baseNode, _recordhash);

        bytes[] memory _name = new bytes[](7);
        _name[0] = "never";
        _name[1] = "gonna";
        _name[2] = "give";
        _name[3] = "you";
        _name[4] = "up";
        _name[5] = "vitalik";
        _name[6] = "eth";
        bytes32 _namehash; // Full namehash
        (_namehash, _encoded) = utils.Encode(_name);
        (string memory _path, string memory _domain) = utils.Format(_encoded);
        bytes memory _request = abi.encodeWithSelector(iResolver.text.selector, _namehash, "avatar");
        string memory _recType = gateway.funcToJson(_request);
        bytes32 _checkhash = keccak256(
            abi.encodePacked(address(ccip2eth), blockhash(block.number - 1), address(this), _domain, _recType, _request)
        );
        assertEq(_path, "eth/vitalik/up/you/give/gonna/never");
        vm.expectRevert(
            abi.encodeWithSelector(
                iENSIP10.OffchainLookup.selector,
                address(ccip2eth),
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _recType), uint256(_checkhash)
                ),
                abi.encodePacked(uint16(block.timestamp / 60)),
                ccip2eth.__callback.selector,
                abi.encode(_baseNode, block.number - 1, _checkhash, _domain, _recType, _path, _encoded, _request)
            )
        );
        ccip2eth.resolve(_encoded, _request);
    }

    /// @dev CCIP end-to-end test with on-chain signer
    function test1_06_CCIPCallbackApprovedOnChain() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "00081";
        _name[1] = "eth";
        (bytes32 _node, bytes memory _encoded) = utils.Encode(_name);
        address _owner = ENS.owner(_node);

        uint256 SignerKey = 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc;
        address _signer = vm.addr(SignerKey);
        vm.prank(_owner);
        ENS.setOwner(_node, address(this));
        ccip2eth.approve(_node, _signer, true);
        bytes memory _recordhash =
            hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        ccip2eth.setRecordhash(_node, _recordhash);

        (string memory _path, string memory _domain) = utils.Format(_encoded);
        bytes memory _request = abi.encodeWithSelector(iResolver.addr.selector, _node);
        string memory _recType = gateway.funcToJson(_request);
        bytes32 _checkhash = keccak256(
            abi.encodePacked(address(ccip2eth), blockhash(block.number - 1), address(this), _domain, _recType, _request)
        );
        bytes memory _extradata =
            abi.encode(_node, block.number - 1, _checkhash, _domain, _recType, _path, _encoded, _request);
        vm.expectRevert(
            abi.encodeWithSelector(
                iENSIP10.OffchainLookup.selector,
                address(ccip2eth),
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _recType), uint256(_checkhash)
                ),
                abi.encodePacked(uint16(block.timestamp / 60)),
                ccip2eth.__callback.selector,
                _extradata
            )
        );
        ccip2eth.resolve(_encoded, _request);
        bytes memory _result = abi.encode(address(this));
        string memory signRequest = string.concat(
            "Requesting Signature To Update ENS Record\n",
            "\nOrigin: ",
            _domain,
            "\nRecord Type: address/60",
            "\nExtradata: 0x",
            gateway.bytesToHexString(abi.encodePacked(keccak256(_result)), 0),
            "\nSigned By: eip155:",
            chainID,
            ":",
            gateway.toChecksumAddress(address(_signer))
        );
        bytes32 _digest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n", gateway.uintToString(bytes(signRequest).length), signRequest
            )
        );
        assertTrue(ccip2eth.approved(_node, _signer));
        assertTrue(ccip2eth.isApprovedSigner(address(this), _node, _signer));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SignerKey, _digest);
        bytes memory _signature = abi.encodePacked(r, s, v);
        bytes memory _response =
            abi.encodeWithSelector(iCallbackType.signedRecord.selector, _signer, _signature, bytes("0"), _result);
        assertEq(_result, ccip2eth.__callback(_response, _extradata));
    }

    /// @dev CCIP end-to-end test with off-chain signer (with fake parameters)
    function test1_07_CCIPCallbackApprovedOffChain() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "00081";
        _name[1] = "eth";
        (bytes32 _node, bytes memory _encoded) = utils.Encode(_name);

        uint256 OwnerKey = 0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd;
        uint256 SignerKey = 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc;
        address _owner = vm.addr(OwnerKey);
        address _signer = vm.addr(SignerKey);
        vm.prank(ENS.owner(_node));
        ENS.setOwner(_node, _owner);
        bytes memory _recordhash =
            hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        vm.prank(_owner);
        ccip2eth.setRecordhash(_node, _recordhash);

        (string memory _path, string memory _domain) = utils.Format(_encoded);
        bytes memory _request = abi.encodeWithSelector(iResolver.addr.selector, _node);
        string memory _recType = gateway.funcToJson(_request);
        bytes32 _checkhash = keccak256(
            abi.encodePacked(address(ccip2eth), blockhash(block.number - 1), _owner, _domain, _recType, _request)
        );
        bytes memory _extradata =
            abi.encode(_node, block.number - 1, _checkhash, _domain, _recType, _path, _encoded, _request);
        vm.expectRevert(
            abi.encodeWithSelector(
                iENSIP10.OffchainLookup.selector,
                address(ccip2eth),
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _recType), uint256(_checkhash)
                ),
                abi.encodePacked(uint16(block.timestamp / 60)),
                ccip2eth.__callback.selector,
                _extradata
            )
        );
        ccip2eth.resolve(_encoded, _request);
        bytes memory _result = abi.encode(address(this));
        string memory signRequest = string.concat(
            "Requesting Signature To Update ENS Record\n",
            "\nOrigin: ",
            _domain,
            "\nRecord Type: address/60",
            "\nExtradata: 0x",
            gateway.bytesToHexString(abi.encodePacked(keccak256(_result)), 0),
            "\nSigned By: eip155:",
            chainID,
            ":",
            gateway.toChecksumAddress(address(_signer))
        );
        bytes32 _digest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n", gateway.uintToString(bytes(signRequest).length), signRequest
            )
        );
        assertTrue(!ccip2eth.approved(_node, _signer));
        assertTrue(!ccip2eth.isApprovedSigner(address(this), _node, _signer));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SignerKey, _digest);
        bytes memory _recordSig = abi.encodePacked(r, s, v);
        signRequest = string.concat(
            "Requesting Signature To Approve ENS Records Signer\n",
            "\nOrigin: ",
            _domain,
            "\nApproved Signer: eip155:",
            chainID,
            ":",
            gateway.toChecksumAddress(_signer),
            "\nApproved By: eip155:",
            chainID,
            ":",
            gateway.toChecksumAddress(_owner)
        );
        _digest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n", gateway.uintToString(bytes(signRequest).length), signRequest
            )
        );
        (v, r, s) = vm.sign(OwnerKey, _digest);
        bytes memory _approvedSig = abi.encodePacked(r, s, v);
        bytes memory _response =
            abi.encodeWithSelector(iCallbackType.signedRecord.selector, _signer, _recordSig, _approvedSig, _result);
        assertEq(_result, ccip2eth.__callback(_response, _extradata));
    }

    /// @dev CCIP end-to-end with off-chain signer and real parameters
    function test1_08_CCIPCallbackApprovedOffChain_WithRealParameters() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "00081";
        _name[1] = "eth";
        (bytes32 _node, bytes memory _encoded) = utils.Encode(_name);

        uint256 OwnerKey = 0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd;
        uint256 SignerKey = 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc;
        address _owner = vm.addr(OwnerKey);
        address _signer = vm.addr(SignerKey);
        vm.prank(ENS.owner(_node));
        ENS.setOwner(_node, _owner);
        bytes memory _recordhash =
            hex"e501017200240801122008dd085b86d16226791544f4628c4efc0936c69221fef17dfac843d9713233bb";
        vm.prank(_owner);
        ccip2eth.setRecordhash(_node, _recordhash);

        (string memory _path, string memory _domain) = utils.Format(_encoded);
        bytes memory _request = abi.encodeWithSelector(iResolver.addr.selector, _node);
        string memory _recType = gateway.funcToJson(_request);
        bytes32 _checkhash = keccak256(
            abi.encodePacked(address(ccip2eth), blockhash(block.number - 1), _owner, _domain, _recType, _request)
        );
        bytes memory _extradata =
            abi.encode(_node, block.number - 1, _checkhash, _domain, _recType, _path, _encoded, _request);
        vm.expectRevert(
            abi.encodeWithSelector(
                iENSIP10.OffchainLookup.selector,
                address(ccip2eth),
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _recType), uint256(_checkhash)
                ),
                abi.encodePacked(uint16(block.timestamp / 60)),
                ccip2eth.__callback.selector,
                _extradata
            )
        );
        ccip2eth.resolve(_encoded, _request);
        bytes memory _result = abi.encode(address(0x1111000000000000000000000000000000000001));
        string memory signRequest = string.concat(
            "Requesting Signature To Update ENS Record\n",
            "\nOrigin: ",
            _domain,
            "\nRecord Type: address/60",
            "\nExtradata: 0x",
            gateway.bytesToHexString(abi.encodePacked(keccak256(_result)), 0),
            "\nSigned By: eip155:",
            chainID,
            ":",
            gateway.toChecksumAddress(address(_signer))
        );
        bytes32 _digest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n", gateway.uintToString(bytes(signRequest).length), signRequest
            )
        );
        assertTrue(!ccip2eth.approved(_node, _signer));
        assertTrue(!ccip2eth.isApprovedSigner(address(this), _node, _signer));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SignerKey, _digest);
        bytes memory _recordSig = abi.encodePacked(r, s, v);
        signRequest = string.concat(
            "Requesting Signature To Approve ENS Records Signer\n",
            "\nOrigin: ",
            _domain,
            "\nApproved Signer: eip155:",
            chainID,
            ":",
            gateway.toChecksumAddress(_signer),
            "\nApproved By: eip155:",
            chainID,
            ":",
            gateway.toChecksumAddress(_owner)
        );
        _digest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n", gateway.uintToString(bytes(signRequest).length), signRequest
            )
        );
        (v, r, s) = vm.sign(OwnerKey, _digest);
        bytes memory _approvedSig = abi.encodePacked(r, s, v);
        bytes memory _response =
            abi.encodeWithSelector(iCallbackType.signedRecord.selector, _signer, _recordSig, _approvedSig, _result);
        assertEq(_result, ccip2eth.__callback(_response, _extradata));
    }

    /// @dev Test setting regular and short recordhash
    function test1_09_SetRecordHash() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "00081";
        _name[1] = "eth";
        (bytes32 _namehash,) = utils.Encode(_name);
        address _addr = ENS.owner(_namehash);
        bytes memory _recordhash =
            hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        vm.prank(_addr);
        ccip2eth.setRecordhash(_namehash, _recordhash);
        bytes32 shorthash = 0x3c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c;
        vm.prank(_addr);
        ccip2eth.setShortRecordhash(_namehash, shorthash);
        assertEq(_recordhash, ccip2eth.getRecordhash(_namehash));
    }

    /// @dev Test setting recordhash for subdomain
    function test1_10_SetSubRecordhash() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "00081";
        _name[1] = "eth";
        (bytes32 _node,) = utils.Encode(_name);
        vm.prank(ENS.owner(_node));
        ENS.setOwner(_node, EOA);
        bytes memory _recordhash =
            hex"e501017200240801122008dd085b86d16226791544f4628c4efc0936c69221fef17dfac843d9713233bb";
        ccip2eth.setSubRecordhash(_node, "test", _recordhash);
        vm.expectRevert(abi.encodeWithSelector(CCIP2ETH.NotAuthorised.selector, "NOT_APPROVED"));
        vm.prank(address(0xc0ffee));
        ccip2eth.setSubRecordhash(_node, "test", _recordhash);
    }

    /// @dev Test setting deep recordhash
    function test1_11_SetDeepSubRecordhash() public {
        string[] memory _subdomains = new string[](2);
        _subdomains[0] = "hello";
        _subdomains[1] = "world";
        bytes[] memory _name = new bytes[](2);
        _name[0] = "domain";
        _name[1] = "eth";
        (bytes32 _node, bytes memory _encoded) = utils.Encode(_name);
        vm.prank(ENS.owner(_node));
        ENS.setOwner(_node, EOA);
        bytes memory _recordhash =
            hex"e501017200240801122008dd085b86d16226791544f4628c4efc0936c69221fef17dfac843d9713233bb";
        ccip2eth.setDeepSubRecordhash(_node, _subdomains, _recordhash);
        vm.expectRevert(abi.encodeWithSelector(CCIP2ETH.NotAuthorised.selector, "NOT_APPROVED"));
        vm.prank(address(0xc0ffee));
        ccip2eth.setDeepSubRecordhash(_node, _subdomains, _recordhash);
        _encoded;
    }

    /// @dev Test getting recordhash and ownerhash
    function test1_12_GetRecordhash() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "00081";
        _name[1] = "eth";
        (bytes32 _node, bytes memory _encoded) = utils.Encode(_name);
        address _owner = ENS.owner(_node);
        bytes memory _recordhash = ccip2eth.getRecordhash(_node);
        bytes memory _ownerhash = ccip2eth.getRecordhash(bytes32(uint256(uint160(_owner))));
        assertEq(_recordhash, bytes(""));
        assertEq(_ownerhash, bytes(""));
        bytes memory _recordhash_ =
            hex"e501017200240801122008dd085b86d16226791544f4628c4efc0936c69221fef17dfac843d9713233bb";
        vm.prank(_owner);
        ccip2eth.setRecordhash(_node, _recordhash_);
        bytes memory __recordhash = ccip2eth.getRecordhash(_node);
        assertEq(__recordhash, _recordhash_);
        bytes memory _ownerhash_ =
            hex"e50101720024080112200000000000000000000000000000000c0936c69221fef17dfac843d971323300";
        vm.prank(_owner);
        ccip2eth.setOwnerhash(_ownerhash_);
        bytes memory __ownerhash = ccip2eth.getRecordhash(bytes32(uint256(uint160(_owner))));
        assertEq(__ownerhash, _ownerhash_);
        _encoded;
    }
}

/**
 * @author freetib.eth, sshmatrix.eth
 * @title CCIP2.eth Resolver tester
 * Note Tests wrapped domains
 */
contract CCIP2ETHTestWrapped is Test {
    error OffchainLookup(address sender, string[] urls, bytes callData, bytes4 callbackFunction, bytes extraData);

    address EOA = address(this);
    CCIP2ETH public ccip2eth;
    iGatewayManager public gateway;
    xENS public ENS = xENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);
    uint256 public PrivateKeyOwner = 0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd;
    uint256 public PrivateKeySigner = 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc;

    Utils public utils = new Utils();
    string chainID;

    /// @dev Setup
    bytes32 dotETH = keccak256(abi.encodePacked(bytes32(0), keccak256("eth")));

    function setUp() public {
        gateway = new GatewayManager();
        chainID = gateway.uintToString(block.chainid);
        ccip2eth = new CCIP2ETH(address(gateway));
    }

    /// @dev Console logs
    function test2_01_ConsoleLog() public view {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "g100kcat";
        _name[1] = "eth";
        (bytes32 _namehash, bytes memory _encoded) = utils.Encode(_name);
        address _addr = ENS.owner(_namehash);
        _encoded;
        _addr;
        //console.log(_addr);
    }

    /// @dev Test CCIP-Read call for a domain
    function test2_02_ResolveLevel2() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "g100kcat";
        _name[1] = "eth";
        (bytes32 _namehash, bytes memory _encoded) = utils.Encode(_name);
        address _addr = ENS.owner(_namehash);
        bytes memory _recordhash =
            hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        vm.prank(_addr);
        ccip2eth.setRecordhash(_namehash, _recordhash);
        (string memory _path, string memory _domain) = utils.Format(_encoded);
        bytes memory _request = abi.encodeWithSelector(iResolver.addr.selector, _namehash);
        string memory _recType = gateway.funcToJson(_request);
        bytes32 _checkhash = keccak256(
            abi.encodePacked(address(ccip2eth), blockhash(block.number - 1), _addr, _domain, _recType, _request)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                iENSIP10.OffchainLookup.selector,
                address(ccip2eth),
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _recType), uint256(_checkhash)
                ),
                abi.encodePacked(uint16(block.timestamp / 60)),
                ccip2eth.__callback.selector,
                abi.encode(_namehash, block.number - 1, _checkhash, _domain, _recType, _path, _encoded, _request)
            )
        );
        ccip2eth.resolve(_encoded, _request);
    }

    /// @dev Test subdomain-level CCIP-Read call
    function test2_03_ResolveLevel3() public {
        bytes[] memory _name = new bytes[](3);
        _name[0] = "0";
        _name[1] = "g100kcat";
        _name[2] = "eth";
        (bytes32 _namehash, bytes memory _encoded) = utils.Encode(_name);
        address _addr = ENS.owner(_namehash);
        vm.prank(_addr);
        ENS.setOwner(_namehash, address(this));
        bytes memory _recordhash =
            hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        ccip2eth.setRecordhash(_namehash, _recordhash);
        (string memory _path, string memory _domain) = utils.Format(_encoded);
        bytes memory _request = abi.encodeWithSelector(iResolver.text.selector, _namehash, abi.encode(string("avatar")));
        string memory _recType = gateway.funcToJson(_request);
        bytes32 _checkhash = keccak256(
            abi.encodePacked(address(ccip2eth), blockhash(block.number - 1), address(this), _domain, _recType, _request)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                iENSIP10.OffchainLookup.selector,
                address(ccip2eth),
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _recType), uint256(_checkhash)
                ),
                abi.encodePacked(uint16(block.timestamp / 60)),
                ccip2eth.__callback.selector,
                abi.encode(_namehash, block.number - 1, _checkhash, _domain, _recType, _path, _encoded, _request)
            )
        );
        ccip2eth.resolve(_encoded, _request);
    }

    /// @dev Test deep CCIP-Read call
    function test2_04_ResolveLevel7() public {
        bytes[] memory _base = new bytes[](2);
        _base[0] = "g100kcat";
        _base[1] = "eth";
        (bytes32 _baseNode, bytes memory _encoded) = utils.Encode(_base);
        address _addr = ENS.owner(_baseNode);
        vm.prank(_addr);
        ENS.setOwner(_baseNode, address(this)); // Owner records set at level 2 only
        bytes memory _recordhash =
            hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        ccip2eth.setRecordhash(_baseNode, _recordhash);

        bytes[] memory _name = new bytes[](7);
        _name[0] = "never";
        _name[1] = "gonna";
        _name[2] = "give";
        _name[3] = "you";
        _name[4] = "up";
        _name[5] = "g100kcat";
        _name[6] = "eth";
        bytes32 _namehash; // Full namehash
        (_namehash, _encoded) = utils.Encode(_name);
        (string memory _path, string memory _domain) = utils.Format(_encoded);
        bytes memory _request = abi.encodeWithSelector(iResolver.text.selector, _namehash, "avatar");
        string memory _recType = gateway.funcToJson(_request);
        bytes32 _checkhash = keccak256(
            abi.encodePacked(address(ccip2eth), blockhash(block.number - 1), address(this), _domain, _recType, _request)
        );
        assertEq(_path, "eth/g100kcat/up/you/give/gonna/never");
        vm.expectRevert(
            abi.encodeWithSelector(
                iENSIP10.OffchainLookup.selector,
                address(ccip2eth),
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _recType), uint256(_checkhash)
                ),
                abi.encodePacked(uint16(block.timestamp / 60)),
                ccip2eth.__callback.selector,
                abi.encode(_baseNode, block.number - 1, _checkhash, _domain, _recType, _path, _encoded, _request)
            )
        );
        ccip2eth.resolve(_encoded, _request);
    }

    /// @dev CCIP end-to-end test with on-chain signer
    function test2_05_CCIPCallbackApprovedOnChain() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "g100kcat";
        _name[1] = "eth";
        (bytes32 _node, bytes memory _encoded) = utils.Encode(_name);
        address _owner = ENS.owner(_node);

        uint256 SignerKey = 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc;
        address _signer = vm.addr(SignerKey);
        vm.prank(_owner);
        ENS.setOwner(_node, address(this));
        ccip2eth.approve(_node, _signer, true);
        bytes memory _recordhash =
            hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        ccip2eth.setRecordhash(_node, _recordhash);

        (string memory _path, string memory _domain) = utils.Format(_encoded);
        bytes memory _request = abi.encodeWithSelector(iResolver.addr.selector, _node);
        string memory _recType = gateway.funcToJson(_request);
        bytes32 _checkhash = keccak256(
            abi.encodePacked(address(ccip2eth), blockhash(block.number - 1), address(this), _domain, _recType, _request)
        );
        bytes memory _extradata =
            abi.encode(_node, block.number - 1, _checkhash, _domain, _recType, _path, _encoded, _request);
        vm.expectRevert(
            abi.encodeWithSelector(
                iENSIP10.OffchainLookup.selector,
                address(ccip2eth),
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _recType), uint256(_checkhash)
                ),
                abi.encodePacked(uint16(block.timestamp / 60)),
                ccip2eth.__callback.selector,
                _extradata
            )
        );
        ccip2eth.resolve(_encoded, _request);
        bytes memory _result = abi.encode(address(this));
        string memory signRequest = string.concat(
            "Requesting Signature To Update ENS Record\n",
            "\nOrigin: ",
            _domain,
            "\nRecord Type: address/60",
            "\nExtradata: 0x",
            gateway.bytesToHexString(abi.encodePacked(keccak256(_result)), 0),
            "\nSigned By: eip155:",
            chainID,
            ":",
            gateway.toChecksumAddress(address(_signer))
        );
        bytes32 _digest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n", gateway.uintToString(bytes(signRequest).length), signRequest
            )
        );
        assertTrue(ccip2eth.approved(_node, _signer));
        assertTrue(ccip2eth.isApprovedSigner(address(this), _node, _signer));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SignerKey, _digest);
        bytes memory _signature = abi.encodePacked(r, s, v);
        bytes memory _response =
            abi.encodeWithSelector(iCallbackType.signedRecord.selector, _signer, _signature, bytes("0"), _result);
        assertEq(_result, ccip2eth.__callback(_response, _extradata));
    }

    /// @dev CCIP end-to-end test with off-chain signer (with fake parameters)
    function test2_06_CCIPCallbackApprovedOffChain() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "g100kcat";
        _name[1] = "eth";
        (bytes32 _node, bytes memory _encoded) = utils.Encode(_name);

        uint256 OwnerKey = 0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd;
        uint256 SignerKey = 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc;
        address _owner = vm.addr(OwnerKey);
        address _signer = vm.addr(SignerKey);
        vm.prank(ENS.owner(_node));
        ENS.setOwner(_node, _owner);
        bytes memory _recordhash =
            hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        vm.prank(_owner);
        ccip2eth.setRecordhash(_node, _recordhash);

        (string memory _path, string memory _domain) = utils.Format(_encoded);
        bytes memory _request = abi.encodeWithSelector(iResolver.addr.selector, _node);
        string memory _recType = gateway.funcToJson(_request);
        bytes32 _checkhash = keccak256(
            abi.encodePacked(address(ccip2eth), blockhash(block.number - 1), _owner, _domain, _recType, _request)
        );
        bytes memory _extradata =
            abi.encode(_node, block.number - 1, _checkhash, _domain, _recType, _path, _encoded, _request);
        vm.expectRevert(
            abi.encodeWithSelector(
                iENSIP10.OffchainLookup.selector,
                address(ccip2eth),
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _recType), uint256(_checkhash)
                ),
                abi.encodePacked(uint16(block.timestamp / 60)),
                ccip2eth.__callback.selector,
                _extradata
            )
        );
        ccip2eth.resolve(_encoded, _request);
        bytes memory _result = abi.encode(address(this));
        string memory signRequest = string.concat(
            "Requesting Signature To Update ENS Record\n",
            "\nOrigin: ",
            _domain,
            "\nRecord Type: address/60",
            "\nExtradata: 0x",
            gateway.bytesToHexString(abi.encodePacked(keccak256(_result)), 0),
            "\nSigned By: eip155:",
            chainID,
            ":",
            gateway.toChecksumAddress(address(_signer))
        );
        bytes32 _digest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n", gateway.uintToString(bytes(signRequest).length), signRequest
            )
        );
        assertTrue(!ccip2eth.approved(_node, _signer));
        assertTrue(!ccip2eth.isApprovedSigner(address(this), _node, _signer));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SignerKey, _digest);
        bytes memory _recordSig = abi.encodePacked(r, s, v);
        signRequest = string.concat(
            "Requesting Signature To Approve ENS Records Signer\n",
            "\nOrigin: ",
            _domain,
            "\nApproved Signer: eip155:",
            chainID,
            ":",
            gateway.toChecksumAddress(_signer),
            "\nApproved By: eip155:",
            chainID,
            ":",
            gateway.toChecksumAddress(_owner)
        );
        _digest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n", gateway.uintToString(bytes(signRequest).length), signRequest
            )
        );
        (v, r, s) = vm.sign(OwnerKey, _digest);
        bytes memory _approvedSig = abi.encodePacked(r, s, v);
        bytes memory _response =
            abi.encodeWithSelector(iCallbackType.signedRecord.selector, _signer, _recordSig, _approvedSig, _result);
        assertEq(_result, ccip2eth.__callback(_response, _extradata));
    }

    /// @dev CCIP end-to-end with off-chain signer and real parameters
    function test2_07_CCIPCallbackApprovedOffChain_WithRealParameters() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "g100kcat";
        _name[1] = "eth";
        (bytes32 _node, bytes memory _encoded) = utils.Encode(_name);

        uint256 OwnerKey = 0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd;
        uint256 SignerKey = 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc;
        address _owner = vm.addr(OwnerKey);
        address _signer = vm.addr(SignerKey);
        vm.prank(ENS.owner(_node));
        ENS.setOwner(_node, _owner);
        bytes memory _recordhash =
            hex"e501017200240801122008dd085b86d16226791544f4628c4efc0936c69221fef17dfac843d9713233bb";
        vm.prank(_owner);
        ccip2eth.setRecordhash(_node, _recordhash);

        (string memory _path, string memory _domain) = utils.Format(_encoded);
        bytes memory _request = abi.encodeWithSelector(iResolver.addr.selector, _node);
        string memory _recType = gateway.funcToJson(_request);
        bytes32 _checkhash = keccak256(
            abi.encodePacked(address(ccip2eth), blockhash(block.number - 1), _owner, _domain, _recType, _request)
        );
        bytes memory _extradata =
            abi.encode(_node, block.number - 1, _checkhash, _domain, _recType, _path, _encoded, _request);
        vm.expectRevert(
            abi.encodeWithSelector(
                iENSIP10.OffchainLookup.selector,
                address(ccip2eth),
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _recType), uint256(_checkhash)
                ),
                abi.encodePacked(uint16(block.timestamp / 60)),
                ccip2eth.__callback.selector,
                _extradata
            )
        );
        ccip2eth.resolve(_encoded, _request);
        bytes memory _result = abi.encode(address(0x1111000000000000000000000000000000000001));
        string memory signRequest = string.concat(
            "Requesting Signature To Update ENS Record\n",
            "\nOrigin: ",
            _domain,
            "\nRecord Type: address/60",
            "\nExtradata: 0x",
            gateway.bytesToHexString(abi.encodePacked(keccak256(_result)), 0),
            "\nSigned By: eip155:",
            chainID,
            ":",
            gateway.toChecksumAddress(address(_signer))
        );
        bytes32 _digest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n", gateway.uintToString(bytes(signRequest).length), signRequest
            )
        );
        assertTrue(!ccip2eth.approved(_node, _signer));
        assertTrue(!ccip2eth.isApprovedSigner(address(this), _node, _signer));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SignerKey, _digest);
        bytes memory _recordSig = abi.encodePacked(r, s, v);
        signRequest = string.concat(
            "Requesting Signature To Approve ENS Records Signer\n",
            "\nOrigin: ",
            _domain,
            "\nApproved Signer: eip155:",
            chainID,
            ":",
            gateway.toChecksumAddress(_signer),
            "\nApproved By: eip155:",
            chainID,
            ":",
            gateway.toChecksumAddress(_owner)
        );
        _digest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n", gateway.uintToString(bytes(signRequest).length), signRequest
            )
        );
        (v, r, s) = vm.sign(OwnerKey, _digest);
        bytes memory _approvedSig = abi.encodePacked(r, s, v);
        bytes memory _response =
            abi.encodeWithSelector(iCallbackType.signedRecord.selector, _signer, _recordSig, _approvedSig, _result);
        assertEq(_result, ccip2eth.__callback(_response, _extradata));
    }

    /// @dev Test setting regular and short recordhash
    function test2_08_SetRecordHash() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "g100kcat";
        _name[1] = "eth";
        (bytes32 _namehash,) = utils.Encode(_name);
        address _addr = ENS.owner(_namehash);
        bytes memory _recordhash =
            hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        vm.prank(_addr);
        ccip2eth.setRecordhash(_namehash, _recordhash);
        bytes32 shorthash = 0x3c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c;
        vm.prank(_addr);
        ccip2eth.setShortRecordhash(_namehash, shorthash);
        assertEq(_recordhash, ccip2eth.getRecordhash(_namehash));
    }

    /// @dev Test setting recordhash for subdomain
    function test2_09_SetSubRecordhash() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "g100kcat";
        _name[1] = "eth";
        (bytes32 _node,) = utils.Encode(_name);
        vm.prank(ENS.owner(_node));
        ENS.setOwner(_node, EOA);
        bytes memory _recordhash =
            hex"e501017200240801122008dd085b86d16226791544f4628c4efc0936c69221fef17dfac843d9713233bb";
        ccip2eth.setSubRecordhash(_node, "test", _recordhash);
        vm.expectRevert(abi.encodeWithSelector(CCIP2ETH.NotAuthorised.selector, "NOT_APPROVED"));
        vm.prank(address(0xc0ffee));
        ccip2eth.setSubRecordhash(_node, "test", _recordhash);
    }

    /// @dev Test setting deep recordhash
    function test2_10_SetDeepSubRecordhash() public {
        string[] memory _subdomains = new string[](2);
        _subdomains[0] = "hello";
        _subdomains[1] = "world";
        bytes[] memory _name = new bytes[](2);
        _name[0] = "g100kcat";
        _name[1] = "eth";
        (bytes32 _node, bytes memory _encoded) = utils.Encode(_name);
        vm.prank(ENS.owner(_node));
        ENS.setOwner(_node, EOA);
        bytes memory _recordhash =
            hex"e501017200240801122008dd085b86d16226791544f4628c4efc0936c69221fef17dfac843d9713233bb";
        ccip2eth.setDeepSubRecordhash(_node, _subdomains, _recordhash);
        vm.expectRevert(abi.encodeWithSelector(CCIP2ETH.NotAuthorised.selector, "NOT_APPROVED"));
        vm.prank(address(0xc0ffee));
        ccip2eth.setDeepSubRecordhash(_node, _subdomains, _recordhash);
        _encoded;
    }

    /// @dev Test getting recordhash and ownerhash
    function test2_11_GetRecordhash() public {
        bytes[] memory _name = new bytes[](2);
        _name[0] = "g100kcat";
        _name[1] = "eth";
        (bytes32 _node, bytes memory _encoded) = utils.Encode(_name);
        address _owner = ENS.owner(_node);
        bytes memory _recordhash = ccip2eth.getRecordhash(_node);
        bytes memory _ownerhash = ccip2eth.getRecordhash(bytes32(uint256(uint160(_owner))));
        assertEq(_recordhash, bytes(""));
        assertEq(_ownerhash, bytes(""));
        bytes memory _recordhash_ =
            hex"e501017200240801122008dd085b86d16226791544f4628c4efc0936c69221fef17dfac843d9713233bb";
        vm.prank(_owner);
        ccip2eth.setRecordhash(_node, _recordhash_);
        bytes memory __recordhash = ccip2eth.getRecordhash(_node);
        assertEq(__recordhash, _recordhash_);
        bytes memory _ownerhash_ =
            hex"e50101720024080112200000000000000000000000000000000c0936c69221fef17dfac843d971323300";
        vm.prank(_owner);
        ccip2eth.setOwnerhash(_ownerhash_);
        bytes memory __ownerhash = ccip2eth.getRecordhash(bytes32(uint256(uint160(_owner))));
        assertEq(__ownerhash, _ownerhash_);
        _encoded;
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

    function getBytes(bytes calldata _b, uint256 _start, uint256 _end) external pure returns (bytes memory) {
        return _b[_start:_end == 0 ? _b.length : _end];
    }
}
