// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >=0.8.15;

import "./Gateway.sol";
/**
 * @title : ENS Off-chain Records Manager
 * @author : freetib.eth, sshmatrix.eth
 */

contract CCIP2ETH is iCCIP2ETH, Gateway {
    /// @notice : ONLY TESTNET
    /// TODO : Remove before mainnet deployment
    function immolate() external {
        require(msg.sender == owner, "NOT_OWNER");
        selfdestruct(payable(owner));
    }

    /// @dev : ENS contract
    iENS public immutable ENS = iENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);

    /// @dev : revert on fallback
    fallback() external payable {
        revert();
    }

    /// @dev : revert on receive
    receive() external payable {
        revert();
    }

    string public chainID = "1";

    function setChainId() external {
        chainID = uintToString(block.chainid);
    }

    /// @dev constructor initial setup
    constructor() {
        isWrapper[0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401] = true;
        emit UpdateWrapper(0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401, true);

        isWrapper[0x114D4603199df73e7D157787f8778E21fCd13066] = true; // goerli
        emit UpdateWrapper(0x114D4603199df73e7D157787f8778E21fCd13066, true);
    }

    /// @dev ENSIP10 : CCIP-read Off-chain Lookup method (https://eips.ethereum.org/EIPS/eip-3668)
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
    mapping(bytes32 => bytes) public contenthash; // contenthash; use IPNS for gasless dynamic record updates, or IPFS for static hosting
    mapping(bytes32 => bool) public manager; // ?? there are multiple approved/isApprovedForAll in all ENS
    mapping(address => bool) public isWrapper;

    /**
     * @dev Interface Selector
     * @param interfaceID : interface identifier
     */
    function supportsInterface(bytes4 interfaceID) external pure returns (bool) {
        return (
            interfaceID == iENSIP10.resolve.selector || interfaceID == iCCIP2ETH.setRecordhash.selector
                || interfaceID == type(iERC173).interfaceId || interfaceID == iCCIP2ETH.__callback.selector
                || interfaceID == iERC165.supportsInterface.selector
        );
    }

    modifier isAuthorized(bytes32 _node) {
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        if (
            msg.sender != _owner && !manager[keccak256(abi.encodePacked("manage-one", _node, _owner, msg.sender))]
                && !manager[keccak256(abi.encodePacked("manage-all", _owner, msg.sender))]
        ) revert NotAuthorized(_node, msg.sender);
        _;
    }
    /**
     * @dev sets contenthash
     * @param _node : ens mode
     * @param _contenthash : contenthash to set
     */

    function setRecordhash(bytes32 _node, bytes calldata _contenthash) external isAuthorized(_node) {
        //require(bytes4(_contenthash[:4]) == hex"e5010172" || bytes3(_contenthash[:3]) == hex"e30101", "IPFS/IPNS_ONLY");
        contenthash[_node] = _contenthash;
        emit ContenthashChanged(_node, _contenthash);
    }

    event ContenthashChanged(bytes32 indexed _node, bytes _contenthash);
    /**
     * Setup IPNS contenthash and manager address in same tx
     * @param _node : namehash of node
     * @param _manager : manager address
     * @param _ipns : ipns contenthash
     */

    function fastSetup(bytes32 _node, address _manager, bytes calldata _ipns) external {
        //require(bytes4(_ipns[:4]) == hex"e5010172" || bytes3(_ipns[:3]) == hex"e30101", "IPFS/IPNS_ONLY");
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        if (msg.sender != _owner && !manager[keccak256(abi.encodePacked("manage-all", _owner, msg.sender))]) {
            revert NotAuthorized(_node, msg.sender);
        }

        contenthash[_node] = _ipns;
        emit ContenthashChanged(_node, _ipns);
        manager[keccak256(abi.encodePacked("manage-one", _node, _owner, _manager))] = true;
        emit Approved(msg.sender, _node, _manager, true);
    }

    /**
     * @dev core Resolve function
     * @param name : ENS name to resolve, DNS encoded
     * @param data : data encoding specific resolver function
     * @return : triggers offchain lookup so return value is never used directly
     */

    function resolve(bytes calldata name, bytes calldata data) external view returns (bytes memory) {
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
                _path = string.concat(string(_labels[index]), "/", _path);
                ++index;
            }

            //bool dotETH = (keccak256(abi.encodePacked(bytes32(0), keccak256(_labels[index - 1]))) == roothash);

            bytes32 _namehash = keccak256(abi.encodePacked(bytes32(0), keccak256(bytes(_labels[--index]))));
            bytes32 _node;
            bytes memory _ipns;
            while (index > 0) {
                _namehash = keccak256(abi.encodePacked(_namehash, keccak256(bytes(_labels[--index]))));
                if (contenthash[_namehash].length > 0) {
                    _ipns = contenthash[_namehash];
                    _node = _namehash;
                }
            }

            require(_namehash == bytes32(data[4:36]), "BAD_NAMEHASH");

            if (_ipns.length == 0) {
                revert ContenthashNotSet(_namehash);
            }

            //bytes4 func = bytes4(data[:4]);
            string memory _jsonPath = funcToJson(data);
            bytes32 _checkHash = keccak256(abi.encodePacked(THIS, blockhash(block.number - 1), _domain, _jsonPath));
            revert OffchainLookup(
                THIS,
                randomGateways(
                    _ipns,
                    string.concat(
                        //_ipns[0] == 0xe5 ? "/ipns/f" : "/ipfs/f",
                        //bytesToString(_ipns, 2),
                        "/.well-known/",
                        _path,
                        "/",
                        _jsonPath
                    ),
                    uint256(_checkHash)
                ),
                abi.encodePacked(uint64(block.timestamp / 60) * 60),
                iCCIP2ETH.__callback.selector,
                abi.encode(block.number - 1, _node, _checkHash, _domain, _jsonPath)
            );
        }
    }

    /**
     * @dev callback function
     * @param response : response of HTTP call
     * @param extradata: extra data used by callback
     */

    function __callback(bytes calldata response, bytes calldata extradata)
        external
        view
        returns (bytes memory result)
    {
        (uint256 _blocknumber, bytes32 _node, bytes32 _checkHash, string memory _domain, string memory _jsonPath) =
            abi.decode(extradata, (uint256, bytes32, bytes32, string, string));

        /// @dev: timeout in 3 blocks
        require(
            block.number <= _blocknumber + 3
                && _checkHash == keccak256(abi.encodePacked(THIS, blockhash(_blocknumber), _domain, _jsonPath)),
            "INVALID_CHECKSUM/TIMEOUT"
        );
        address _signer;
        bytes memory signature;
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        string memory _req;
        string memory _ByStr = string.concat("eip155:", chainID, ":", toChecksumAddress(_signer));
        if (bytes4(response[:4]) == iCCIP2ETH.__callback.selector) {
            (_signer, signature, result) = abi.decode(response[4:], (address, bytes, bytes));
        } else if (bytes4(response[:4]) == iResolver.approved.selector) {
            bytes memory _approved;
            (_signer, signature, _approved, result) = abi.decode(response[4:], (address, bytes, bytes, bytes));
            _req = string.concat(
                "Requesting Signature To Approve Off-Chain ENS Records Manager\n",
                "\nENS Domain: ",
                _domain,
                "\nRecords Manager: ",
                _ByStr,
                "\nSigned By: ",
                "eip155:",
                chainID,
                ":",
                toChecksumAddress(_owner)
            );
            if (
                !iCCIP2ETH(THIS).validSignature(
                    _owner,
                    keccak256(
                        abi.encodePacked("\x19Ethereum Signed Message:\n", uintToString(bytes(_req).length), _req)
                    ),
                    _approved
                )
            ) {
                revert InvalidSignature("BAD_APPROVAL_SIG");
            }
        } else {
            revert InvalidSignature("BAD_PREFIX");
        }
        //(_signer, signature, result) = abi.decode(response[4:], (address, bytes, bytes));
        _req = string.concat(
            "Requesting Signature To Update Off-Chain ENS Record\n",
            //"\nIMPORTANT: Please verify the integrity and authenticity of connected Off-chain ENS Records Manager before signing this message\n",
            "\nENS Domain: ",
            _domain,
            "\nRecord Type: ",
            _jsonPath,
            "\nExtradata: 0x",
            bytesToString(abi.encodePacked(keccak256(result)), 0),
            "\nSigned By:",
            _ByStr
        );
        bytes32 _digest =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", uintToString(bytes(_req).length), _req));
        if (!iCCIP2ETH(THIS).validSignature(_signer, _digest, signature)) {
            revert InvalidSignature("BAD_SIGNER");
        }
        if (
            _signer != _owner && !manager[keccak256(abi.encodePacked("manage-one", _node, _owner, _signer))]
                && !manager[keccak256(abi.encodePacked("manage-all", _owner, _signer))]
        ) revert NotAuthorized(_node, _signer);
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
        if (signature.length == 64) {
            bytes32 vs = bytes32(signature[32:]);
            s = vs & bytes32(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
            v = uint8((uint256(vs) >> 255) + 27);
        } else if (signature.length == 65) {
            s = bytes32(signature[32:64]);
            v = uint8(bytes1(signature[64:]));
        } else if (signature.length == 96) {
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

    /// @dev : Resolver/Approval Management functions

    function setApprovalForAll(address _signer, bool _approved) external {
        manager[keccak256(abi.encodePacked("manage-all", msg.sender, _signer))] = _approved;
        emit ApprovalForAll(msg.sender, _signer, _approved);
    }

    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    event Approved(address owner, bytes32 indexed node, address indexed delegate, bool indexed approved);

    /**
     * @dev isApprovedForAll
     */
    function isApprovedForAll(address _owner, address _signer) public view returns (bool) {
        return manager[keccak256(abi.encodePacked("manage-all", _owner, _signer))];
    }

    /**
     * @dev Approve a delegate to be able to updated records on a node.
     */
    function approve(bytes32 _node, address _signer, bool _approved) external {
        manager[keccak256(abi.encodePacked("manage-one", _node, msg.sender, _signer))] = _approved;
        emit Approved(msg.sender, _node, _signer, _approved);
    }

    /**
     * @dev Check to see if the delegate has been approved by the owner for the node.
     */
    function isApprovedFor(address _owner, bytes32 _node, address _signer) public view returns (bool) {
        return manager[keccak256(abi.encodePacked("manage-one", _node, _owner, _signer))];
    }

    /**
     * Check if _signer is approved to manage _node records
     * @param _node : namehash of node
     * @param _signer : address of manager
     */

    function approved(bytes32 _node, address _signer) public view returns (bool) {
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        return _owner == _signer || manager[keccak256(abi.encodePacked("manage-one", _node, _owner, _signer))]
            || manager[keccak256(abi.encodePacked("manage-all", _owner, _signer))];
    }

    event UpdateWrapper(address indexed _new, bool indexed _ok);
    /// @dev : dev only ??manage future upgrades in ENS wrapper??

    function updateWrapper(address _addr, bool _set) external onlyDev {
        require(_addr.code.length > 0, "Only Contract");
        isWrapper[_addr] = _set;
        emit UpdateWrapper(_addr, _set);
    }

    function updateWrappers(address[] calldata _addrs, bool[] calldata _sets) external onlyDev {
        uint256 len = _addrs.length;
        require(len == _sets.length, "BAD_LENGTH");
        for (uint256 i = 0; i < len; i++) {
            require(_addrs[i].code.length > 0, "Only Contract");
            isWrapper[_addrs[i]] = _sets[i];
            emit UpdateWrapper(_addrs[i], _sets[i]);
        }
    }
}
