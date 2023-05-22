// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >=0.8.15;

import "./GatewayManager.sol";
/**
 * @title ENS Off-chain Records Manager
 * @author freetib.eth, sshmatrix.eth
 */

contract CCIP2ETH is iCCIP2ETH {
    /// @notice ONLY TESTNET
    /// TODO Remove before mainnet deployment
    function immolate() external {
        address _owner = gateway.owner();
        require(msg.sender == _owner, "NOT_OWNER");
        selfdestruct(payable(_owner));
    }

    /// @dev ENS contract
    iENS public immutable ENS = iENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);
    iGateway public gateway; // utils and extra functions
    /// @dev constructor initial setup

    constructor() {
        gateway = new GatewayManager();

        //isWrapper[address(gateway)] = true; // set ipfs2.eth resolver here
        //emit UpdateWrapper(address(gateway), true); // set ipfs2.eth resolver here

        isWrapper[address(this)] = true;
        emit UpdateWrapper(address(this), true);

        isWrapper[0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401] = true;
        emit UpdateWrapper(0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401, true);

        isWrapper[0x114D4603199df73e7D157787f8778E21fCd13066] = true; // goerli
        emit UpdateWrapper(0x114D4603199df73e7D157787f8778E21fCd13066, true);

        supportsInterface[iERC165.supportsInterface.selector] = true;
        supportsInterface[iENSIP10.resolve.selector] = true;
        supportsInterface[type(iERC173).interfaceId] = true;
        supportsInterface[iCCIP2ETH.recordhash.selector] = true;
        supportsInterface[iCCIP2ETH.setRecordhash.selector] = true;
    }
    /// @dev revert on fallback

    fallback() external payable {
        revert();
    }

    event ThankYou(address indexed _addr, uint256 indexed _value);
    /// @dev revert on receive

    receive() external payable {
        emit ThankYou(msg.sender, msg.value);
    }

    string public chainID = "1";

    function setChainId() external {
        chainID = gateway.uintToString(block.chainid);
    }

    function updateGatewayManager(address _gm) external {
        require(msg.sender == gateway.owner(), "Only Dev");
        require(msg.sender == iGateway(_gm).owner(), "Invalid Gateway Contract");
        emit UpdateGatewayManager(address(gateway), _gm);
        gateway = iGateway(_gm);
    }

    event UpdateGatewayManager(address indexed _old, address indexed _new);

    /// @dev ENSIP10 CCIP-read Off-chain Lookup method (https://eips.ethereum.org/EIPS/eip-3668)
    error OffchainLookup(
        address _addr, // callback contract)
        string[] _gateways, // CCIP gateway URLs
        bytes _data, // {data} field; request value for HTTP call
        bytes4 _callbackFunction, // callback function
        bytes _extradata // callback extra data
    );

    error InvalidSignature(string _message);
    error NotAuthorized(bytes32 _node, address _addr);
    error ContenthashNotSet(bytes32 _node);

    /// Other Mappings
    mapping(bytes32 => bytes) public recordhash; // contenthash or string url safe base32/36
    mapping(bytes32 => bool) public manager; // ?? there are multiple approved/isApprovedForAll in all ENS
    mapping(address => bool) public isWrapper;
    mapping(bytes4 => bool) public supportsInterface;
    /**
     * @dev sets contenthash
     * @param _node ens mode
     * @param _contenthash contenthash to set
     */

    function setRecordhash(bytes32 _node, bytes calldata _contenthash) external {
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        if (
            msg.sender != _owner && !manager[keccak256(abi.encodePacked("manager", _node, _owner, msg.sender))]
                && !manager[keccak256(abi.encodePacked("manage-all", _owner, msg.sender))]
        ) revert NotAuthorized(_node, msg.sender);
        recordhash[_node] = _contenthash;
        emit RecordhashChanged(_node, _contenthash);
    }

    event RecordhashChanged(bytes32 indexed _node, bytes _contenthash);

    /**
     * @dev ENS Resolve function
     * @param name ENS name to resolve, DNS encoded
     * @param data data encoding specific resolver function
     * @return result triggers offchain lookup so return value is never used directly
     */

    function resolve(bytes calldata name, bytes calldata data) external view returns (bytes memory result) {
        unchecked {
            uint256 index = 1;
            uint256 n = 1;
            uint256 len = uint8(bytes1(name[:1]));
            bytes[] memory _labels = new bytes[](42);
            _labels[0] = name[1:n += len];
            string memory _path = string(_labels[0]);
            string memory _domain = _path;
            while (name[n] > 0x0) {
                len = uint8(bytes1(name[n:++n]));
                _labels[index] = name[n:n += len];
                _domain = string.concat(_domain, ".", string(_labels[index]));
                _path = string.concat(string(_labels[index++]), "/", _path);
            }

            //bool dotETH = (keccak256(abi.encodePacked(bytes32(0), keccak256(_labels[index - 1]))) == roothash);

            bytes32 _namehash = keccak256(abi.encodePacked(bytes32(0), keccak256(_labels[--index])));
            bytes32 _node;
            bytes memory _recordhash; // = recordhash[0];
            while (index > 0) {
                _namehash = keccak256(abi.encodePacked(_namehash, keccak256(_labels[--index])));
                if (ENS.recordExists(_namehash)) {
                    _node = _namehash;
                    _recordhash = recordhash[_namehash];
                } else {
                    //_recordhash = recordhash[_namehash];
                    break;
                }
            }
            //bytes4 func = bytes4(data[:4]);
            //address _resolver = ENS.resolver(_node);
            //console.logAddress(_resolver);
            /*
            if (!isWrapper[_resolver]) {
                // universal redirect mode
                if (iERC165(_resolver).supportsInterface(iERC165.supportsInterface.selector)) {
                    if (iERC165(_resolver).supportsInterface(iENSIP10.resolve.selector)) {
                        return iENSIP10(_resolver).resolve(name, data);
                    } else if (iERC165(_resolver).supportsInterface(func)) {
                        bool ok;
                        (ok, result) = _resolver.staticcall(data);
                        if (!ok || result.length == 0) {
                            // || (result.length == 32 && bytes32(result) == 0x0)) {
                            //? default error/profile page
                            if (func == iResolver.contenthash.selector) {
                                return abi.encode(recordhash[bytes32(uint256(404))]);
                            } else {
                                revert("BAD_RESOLVER");
                            }
                        }
                        return abi.encode(result);
                    }
                }
                revert("INVALID_RESOLVER");
            }*/

            if (_recordhash.length == 0) {
                if (bytes4(data[:4]) == iResolver.contenthash.selector) {
                    return abi.encode(recordhash[bytes32(uint256(404))]);
                }
                revert("RECORD_NOT_SET");
            }
            string memory _suffix = gateway.funcToJson(data);
            bytes32 _checkHash = keccak256(abi.encodePacked(this, blockhash(block.number - 1), _domain, _path, _suffix));
            revert OffchainLookup(
                address(this),
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _suffix), uint256(_checkHash)
                ),
                abi.encodePacked(uint32(block.timestamp / 60) * 60),
                iCCIP2ETH.__callback.selector,
                abi.encode(_node, block.number - 1, _checkHash, _domain, _path, _suffix)
            );
        }
    }

    /**
     * @dev callback function
     * @param response response of HTTP call
     * @param extradata: extra data used by callback
     */

    function __callback(bytes calldata response, bytes calldata extradata)
        external
        view
        returns (bytes memory result)
    {
        (
            bytes32 _node,
            uint256 _blocknumber,
            bytes32 _digest,
            string memory _domain,
            string memory _path,
            string memory _suffix
        ) = abi.decode(extradata, (bytes32, uint256, bytes32, string, string, string));

        /// @dev: timeout in 3 blocks
        require(
            block.number < _blocknumber + 4
                && _digest == keccak256(abi.encodePacked(this, blockhash(_blocknumber), _domain, _path, _suffix)),
            "INVALID_CHECKSUM/TIMEOUT"
        );
        address _signer;
        bytes memory signature;
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        string memory _req;
        bytes4 _type = bytes4(response[:4]);
        if (_type == iCCIP2ETH.recordhash.selector) {
            (_signer, signature, result) = abi.decode(response[4:], (address, bytes, bytes));
            if (_signer != _owner && !manager[keccak256(abi.encodePacked("manager", _node, _owner, _signer))]) {
                revert NotAuthorized(_node, _signer);
            }
        } else if (_type == iResolver.approved.selector) {
            bytes memory _approved;
            (_signer, signature, _approved, result) = abi.decode(response[4:], (address, bytes, bytes, bytes));
            _req = string.concat(
                "Requesting Signature To Approve Off-Chain ENS Records Manager Key\n",
                "\nENS Domain: ",
                _domain,
                "\nApproved For: eip155:1:",
                gateway.toChecksumAddress(_signer),
                "\nSigned By: eip155:1:",
                gateway.toChecksumAddress(_owner)
            );
            if (
                !iCCIP2ETH(this).validSignature(
                    _owner,
                    keccak256(
                        abi.encodePacked(
                            "\x19Ethereum Signed Message:\n", gateway.uintToString(bytes(_req).length), _req
                        )
                    ),
                    _approved
                )
            ) {
                revert InvalidSignature("BAD_APPROVAL_SIG");
            }
        } /*else if (_type == iResolver.???.selector) {
            // custodial subdomain
            // redirect with recursive ccip-read
            // signer = assigned
            // signature is from owner
            // result is not
            uint64 _na;
            uint64 _nb;
            (_signer, _nb, _na, signature, result) = abi.decode(response[4:], (address, uint64, uint64, bytes, bytes));
            require(_na > block.timestamp, "SUBDOMAIN_EXPIRED");
            _req = string.concat(
                "Requesting Signature To Redirect ENS Subdomain Record\n",
                "\nENS Subdomain: ",
                _domain,
                "\nAssigned To: eip155:1:",
                gateway.toChecksumAddress(_signer),
                "\nRedirect Hash: 0x",
                gateway.bytesToHexString(abi.encodePacked(keccak256(result)), 0),
                "\nValidity: ",
                gateway.uintToString(_na),
                " days\nSigned By: eip155:1:",
                gateway.toChecksumAddress(_owner)
            );
            if (
                !iCCIP2ETH(this).validSignature(
                    _owner,
                    keccak256(
                        abi.encodePacked(
                            "\x19Ethereum Signed Message:\n", gateway.uintToString(bytes(_req).length), _req
                        )
                    ),
                    signature
                )
            ) {
                revert InvalidSignature("BAD_APPROVAL_SIG");
            }
        }*/ else {
            revert InvalidSignature("BAD_PREFIX");
        }
        _req = string.concat(
            "Requesting Signature To Update Off-Chain ENS Record\n",
            "\nENS Domain: ",
            _domain,
            "\nRecord Type: ",
            _suffix,
            "\nExtradata: 0x",
            gateway.bytesToHexString(abi.encodePacked(keccak256(result)), 0),
            "\nSigned By: eip155:1:",
            gateway.toChecksumAddress(_signer)
        );
        if (
            !iCCIP2ETH(this).validSignature(
                _signer,
                keccak256(
                    abi.encodePacked("\x19Ethereum Signed Message:\n", gateway.uintToString(bytes(_req).length), _req)
                ),
                signature
            )
        ) {
            revert InvalidSignature("BAD_SIGNER");
        }
    }

    /**
     * @dev check if given signature is valid
     * @param digest hash of signed message
     * @param signature signature to verify
     * @return bool
     * signature is 64 bytes bytes32(R)+bytes32(VS) compact
     * or 65 bytes (bytes32(R)+bytes32(S)+uint8(V)) packed
     * or 96 bytes (bytes32(R)+bytes32(S)+uint256(V)) longest
     */
    function validSignature(address _signer, bytes32 digest, bytes calldata signature) external pure returns (bool) {
        require(_signer != address(0), "ZERO_ADDR");
        bytes32 r = bytes32(signature[:32]);
        bytes32 s;
        uint8 v;
        uint256 len = signature.length;
        if (len == 64) {
            bytes32 vs = bytes32(signature[32:]);
            s = vs & bytes32(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
            v = uint8((uint256(vs) >> 255) + 27);
        } else if (len == 65) {
            s = bytes32(signature[32:64]);
            v = uint8(bytes1(signature[64:]));
        } else if (len == 96) {
            s = bytes32(signature[32:64]);
            v = uint8(uint256(bytes32(signature[64:])));
        } else {
            revert InvalidSignature("BAD_SIG_LENGTH");
        }
        if (s > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert InvalidSignature("INVALID_S_VALUE");
        }
        return (_signer == ecrecover(digest, v, r, s));
    }

    /// @dev Resolver/Approval Management functions

    event Approved(address owner, bytes32 indexed node, address indexed delegate, bool indexed approved);

    function approve(bytes32 _node, address _signer, bool _approved) external {
        manager[keccak256(abi.encodePacked("manager", _node, msg.sender, _signer))] = _approved;
        emit Approved(msg.sender, _node, _signer, _approved);
    }

    function isApprovedFor(address _owner, bytes32 _node, address _signer) public view returns (bool) {
        return manager[keccak256(abi.encodePacked("manager", _node, _owner, _signer))];
    }

    /**
     * Check if _signer is approved to manage _node records
     * @param _node namehash of node
     * @param _signer address of manager
     */

    function approved(bytes32 _node, address _signer) public view returns (bool) {
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        return _owner == _signer || manager[keccak256(abi.encodePacked("manager", _node, _owner, _signer))];
    }

    event UpdateWrapper(address indexed _new, bool indexed _ok);
    /// @dev dev only ??manage future upgrades in ENS wrapper??

    function updateWrapper(address _addr, bool _set) external {
        require(msg.sender == gateway.owner(), "Only Dev");
        require(_addr.code.length > 0, "Only Contract");
        isWrapper[_addr] = _set;
        emit UpdateWrapper(_addr, _set);
    }

    function updateWrappers(address[] calldata _addrs, bool[] calldata _sets) external {
        require(msg.sender == gateway.owner(), "Only Dev");
        uint256 len = _addrs.length;
        require(len == _sets.length, "BAD_LENGTH");
        for (uint256 i = 0; i < len; i++) {
            require(_addrs[i].code.length > 0, "Only Contract");
            isWrapper[_addrs[i]] = _sets[i];
            emit UpdateWrapper(_addrs[i], _sets[i]);
        }
    }
}
