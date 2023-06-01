// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

import "./Interface.sol";

/**
 * @title Off-Chain ENS Records Manager
 * @author freetib.eth, sshmatrix.eth
 * Github : https://github.com/namesys-eth/ccip2-eth-resolver
 * Client : htpps://ccip2.eth.limo
 */
contract CCIP2ETH is iCCIP2ETH {
    /// @dev - ONLY TESTNET
    /// TODO - Remove before Mainnet deployment
    function immolate() external {
        address _owner = gateway.owner();
        require(msg.sender == _owner, "NOT_OWNER");
        selfdestruct(payable(_owner));
    }

    /// Events
    event ThankYou(address indexed addr, uint256 indexed value);
    event UpdateGatewayManager(address indexed oldAddr, address indexed newAddr);
    event RecordhashChanged(bytes32 indexed node, bytes contenthash);
    event UpdateWrapper(address indexed newAddr, bool indexed status);
    event Approved(address owner, bytes32 indexed node, address indexed delegate, bool indexed approved);
    event UpdateSupportedInterface(bytes4 indexed sig, bool indexed status);

    /// Errors

    error InvalidSignature(string message);
    error NotAuthorized(bytes32 node, address addr);
    error ContenthashNotSet(bytes32 node);

    /// @dev - ENS Legacy Registry
    iENS public immutable ENS = iENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);
    /// @dev - CCIP-Read Gateways
    iGatewayManager public gateway;
    /// Mappings
    /// @dev - Global contenthash storing all other records; must be contenthash in base32/36 string URL format
    mapping(bytes32 => bytes) public recordhash;
    /// @dev - On-chain singular manager for all records of a name
    mapping(bytes32 => bool) public manager;
    /// @dev - List of all application wrapping contracts to be declared in contructor
    mapping(address => bool) public isWrapper;
    /// Interfaces
    mapping(bytes4 => bool) public supportsInterface;

    /// @dev - Constructor
    constructor(address _gateway) {
        gateway = iGatewayManager(_gateway);

        /// @dev - IPFS2.eth resolver as Redirect wrapper
        /// @notice iswrapper[] is used for wrappers and internal service resolvers
        /// e.g., ipfs2.eth resolver is msg.sender if it's redirecting specific calls
        /// not required if we don't use universal resolver mode
        //isWrapper[address(0xb4BA47783Ff613ec55c9ECdaF38fCF29D7632048)] = true;
        //emit UpdateWrapper(address(0xb4BA47783Ff613ec55c9ECdaF38fCF29D7632048), true);

        /// @dev - Sets current contract as Wrapper
        /// iswrapper is used to filter service resolvers and wrappers from other contract/EOA types
        /// not required if we don't use universal resolver mode
        // isWrapper[address(this)] = true;
        // emit UpdateWrapper(address(this), true);

        /// @dev - Sets ENS Mainnet wrapper as Wrapper
        isWrapper[0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401] = true;
        emit UpdateWrapper(0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401, true);

        /// @dev - Sets ENS Goerli wrapper as Wrapper; remove before Mainnet deploy [?]
        isWrapper[0x114D4603199df73e7D157787f8778E21fCd13066] = true;
        emit UpdateWrapper(0x114D4603199df73e7D157787f8778E21fCd13066, true);

        /// @dev - Set necessary interfaces
        supportsInterface[iERC165.supportsInterface.selector] = true;
        supportsInterface[iENSIP10.resolve.selector] = true;
        supportsInterface[type(iERC173).interfaceId] = true;
        supportsInterface[iCCIP2ETH.recordhash.selector] = true;
        supportsInterface[iCCIP2ETH.setRecordhash.selector] = true;
    }

    /// @dev - Revert on fallback
    fallback() external payable {
        revert();
    }

    /// @dev - Receive donation
    receive() external payable {
        emit ThankYou(msg.sender, msg.value);
    }

    /**
     * @dev Set new Gateway Manager Contract
     * @param _gateway - address of new Gateway Manager Contract
     */
    function updateGatewayManager(address _gateway) external {
        require(msg.sender == gateway.owner(), "ONLY_DEV");
        require(msg.sender == iGatewayManager(_gateway).owner(), "INVALID_GATEWAY_CONTRACT");
        emit UpdateGatewayManager(address(gateway), _gateway);
        gateway = iGatewayManager(_gateway);
    }

    /**
     * @dev Sets recordhash for a node, only ENS owner/approved address can set
     * @param _node - namehash of ENS (node)
     * @param _contenthash - contenthash to set as recordhash
     */
    function setRecordhash(bytes32 _node, bytes calldata _contenthash) external {
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        if (msg.sender != _owner && !manager[keccak256(abi.encodePacked("manager", _node, _owner, msg.sender))]) {
            revert NotAuthorized(_node, msg.sender);
        }
        recordhash[_node] = _contenthash;
        emit RecordhashChanged(_node, _contenthash);
    }

    /**
     * @dev EIP-2544/EIP-3668 core resolve() function; aka CCIP-Read
     * @param name - ENS name to resolve; must be DNS encoded
     * @param data - data encoding specific function to resolve
     * @return result - triggers Off-chain Lookup; return value is stashed
     */
    function resolve(bytes calldata name, bytes calldata data) external view returns (bytes memory result) {
        unchecked {
            /// @dev - DNSDecode() routine
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

            /// @notice - '.eth' checker
            //bool dotETH = (keccak256(abi.encodePacked(bytes32(0), keccak256(_labels[index - 1]))) == roothash);

            bytes32 _namehash = keccak256(abi.encodePacked(bytes32(0), keccak256(_labels[--index])));
            bytes32 _node;
            bytes memory _recordhash;
            while (index > 0) {
                _namehash = keccak256(abi.encodePacked(_namehash, keccak256(_labels[--index])));
                if (ENS.recordExists(_namehash)) {
                    _node = _namehash;
                    _recordhash = recordhash[_namehash];
                } else {
                    break;
                }
            }

            if (_recordhash.length == 0) {
                if (bytes4(data[:4]) == iResolver.contenthash.selector) {
                    return abi.encode(recordhash[bytes32(uint256(404))]);
                }
                revert("RECORD_NOT_SET");
            }
            string memory _suffix = gateway.funcToJson(data); // filename for the record
            bytes32 _checkHash = keccak256(abi.encodePacked(this, blockhash(block.number - 1), _domain, _path, _suffix));
            revert OffchainLookup(
                address(this), // sender
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _suffix), uint256(_checkHash)
                ), // generate random gateway for resolution
                abi.encodePacked(uint32(block.timestamp / 60) * 60), // current timestamp in seconds
                iCCIP2ETH.__callback.selector, // callback function
                abi.encode(_node, block.number - 1, _checkHash, _domain, _path, _suffix) // callback extradata
            );
        }
    }

    /**
     * @dev Callback function
     * @param response - response of CCIP-Read call
     * @param extradata - extra data used by callback
     */
    function __callback(bytes calldata response, bytes calldata extradata)
        external
        view
        returns (bytes memory result)
    {
        (
            bytes32 _node,
            uint256 _blocknumber,
            bytes32 _digest_,
            string memory _domain,
            string memory _path,
            string memory _suffix
        ) = abi.decode(extradata, (bytes32, uint256, bytes32, string, string, string));

        /// @dev - timeout in 3 blocks
        require(
            block.number < _blocknumber + 4
                && _digest_ == keccak256(abi.encodePacked(this, blockhash(_blocknumber), _domain, _path, _suffix)),
            "INVALID_CHECKSUM/TIMEOUT"
        );
        /// @dev - Init signer from CCIP-Read response
        address _signer;
        /// @dev - Init record-specific signature (RECORD_SIG) from CCIP-Read response
        bytes memory signature;
        /// @notice - Get owner of ENS domain
        address _owner = ENS.owner(_node);
        /// @dev - If name is wrapped (owner = wrapper), assign ownership to user
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        /// @dev - Init off-chain manager signature request string
        string memory signRequest;
        /// @dev - Get signer-type from response identifier
        bytes4 _type = bytes4(response[:4]);
        // Signer-type is on-chain (= recordhash)
        if (_type == iCCIP2ETH.recordhash.selector) {
            // Decode signer, record-specific signature and record from response
            (_signer, signature, result) = abi.decode(response[4:], (address, bytes, bytes));
            if (_signer != _owner && !manager[keccak256(abi.encodePacked("manager", _node, _owner, _signer))]) {
                revert NotAuthorized(_node, _signer);
            }
            // Signer-type is off-chain (= approved)
        } else if (_type == iResolver.approved.selector) {
            /// @dev - Off-chain manager signature (OFF_CHAIN_SIG)
            bytes memory _approvedSignature;
            /// @dev - Decode signer, record-specific signature, off-chain manager signature and record from response
            (_signer, signature, _approvedSignature, result) = abi.decode(response[4:], (address, bytes, bytes, bytes));
            /// @dev - Create off-chain manager signature digest
            signRequest = string.concat(
                "Requesting Signature To Approve Off-Chain ENS Records Signer Key\n",
                "\nENS Domain: ",
                _domain,
                "\nApproved Signer: eip155:1:",
                gateway.toChecksumAddress(_signer),
                "\nSigned By: eip155:1:",
                gateway.toChecksumAddress(_owner)
            );
            /// @dev - Check if the off-chain manager signature is signed by the owner
            if (
                !iCCIP2ETH(this).validSignature(
                    _owner,
                    keccak256(
                        abi.encodePacked(
                            "\x19Ethereum Signed Message:\n",
                            gateway.uintToString(bytes(signRequest).length),
                            signRequest
                        )
                    ),
                    _approvedSignature
                )
            ) {
                revert InvalidSignature("BAD_APPROVAL_SIG");
            }
        } else {
            revert InvalidSignature("BAD_PREFIX");
        }
        /// @dev - Create record update signature digest
        signRequest = string.concat(
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
        /// @dev - Check if the record-specific signature is signed by the expected signer
        if (
            !iCCIP2ETH(this).validSignature(
                _signer,
                keccak256(
                    abi.encodePacked(
                        "\x19Ethereum Signed Message:\n", gateway.uintToString(bytes(signRequest).length), signRequest
                    )
                ),
                signature
            )
        ) {
            revert InvalidSignature("BAD_SIGNER");
        }
    }

    /**
     * @dev Checks if a signature is valid
     * @param _signer - signer of message
     * @param digest - hash of signed message
     * @param signature - compact signature to verify
     * @return bool
     * Signature can be:
     * a) 64 bytes - bytes32(r) + bytes32(vs) ~ compact, or
     * b) 65 bytes - bytes32(r) + bytes32(s) + uint8(v) ~ packed, or
     * c) 96 bytes - bytes32(r) + bytes32(s) + uint256(v) ~ longest.
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

    /**
     * @dev Sets a Signer/Manager as approved to manage records for a node
     * @param _node - namehash of ENS (node)
     * @param _signer - address of Signer/Manager
     * @param _approval - status to set
     */
    function approve(bytes32 _node, address _signer, bool _approval) external {
        manager[keccak256(abi.encodePacked("manager", _node, msg.sender, _signer))] = _approval;
        emit Approved(msg.sender, _node, _signer, _approval);
    }

    /**
     * @dev Check if a Signer/Manager is approved by Owner to manage records for a node
     * @param _owner - address of Owner
     * @param _node - namehash of ENS (node)
     * @param _signer - address of Signer/Manager
     */
    function isApprovedFor(address _owner, bytes32 _node, address _signer) public view returns (bool) {
        return manager[keccak256(abi.encodePacked("manager", _node, _owner, _signer))];
    }

    /**
     * @dev Check if a Signer/Manager is approved to manage records for a node
     * @param _node - namehash of ENS (node)
     * @param _signer - address of Signer/Manager
     */
    function approved(bytes32 _node, address _signer) public view returns (bool) {
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        return _owner == _signer || manager[keccak256(abi.encodePacked("manager", _node, _owner, _signer))];
    }
    /**
     * @dev Updates Supported interface
     * @param _sig - 4 bytes interface selector
     * @param _set - state to set for selector
     */

    function updateSupportedInterface(bytes4 _sig, bool _set) external {
        require(msg.sender == gateway.owner(), "ONLY_DEV");
        supportsInterface[_sig] = _set;
        //emit UpdateSupportedInterface(_sig, _set);
    }

    /**
     * @dev Sets a new wrapper in the list of application wrappers
     * @param _addr - address of new wrapper
     * @param _set - state to set for new wrapper
     */
    function updateWrapper(address _addr, bool _set) external {
        require(msg.sender == gateway.owner(), "ONLY_DEV");
        require(_addr.code.length > 0, "ONLY_CONTRACT");
        isWrapper[_addr] = _set;
        emit UpdateWrapper(_addr, _set);
    }
    /* 
    * Owner 
    */
    function owner() public view returns (address) {
        return gateway.owner();
    }
    /**
     * @dev Withdraw Ether to owner; to be used for tips or in case some Ether gets locked in the contract
     */

    function withdraw() external {
        payable(gateway.owner()).transfer(address(this).balance);
    }

    /**
     * @dev To be used for tips or in case some fungible tokens get locked in the contract
     * @param _token - token address
     * @param _balance - amount to release
     */
    function withdraw(address _token, uint256 _balance) external {
        iToken(_token).transferFrom(address(this), gateway.owner(), _balance);
    }

    /**
     * @dev To be used for tips or in case some non-fungible tokens get locked in the contract
     * @param _token - token address
     * @param _id - token ID to release
     */
    function safeWithdraw(address _token, uint256 _id) external {
        iToken(_token).safeTransferFrom(address(this), gateway.owner(), _id);
    }
}
