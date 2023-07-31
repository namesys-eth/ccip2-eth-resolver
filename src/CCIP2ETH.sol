// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

import "./Interface.sol";

/**
 * @title Off-Chain ENS Records Manager
 * @author freetib.eth, sshmatrix.eth [https://github.com/namesys-eth]
 * Github : https://github.com/namesys-eth/ccip2-eth-resolver
 * Client : https://namesys.eth.limo
 */
contract CCIP2ETH is iCCIP2ETH {
    /// @dev - Revert on fallback
    fallback() external payable {
        revert();
    }

    /// @dev - Receive donation
    receive() external payable {
        emit ThankYou(msg.sender, msg.value);
    }

    /// Events
    event ThankYou(address indexed addr, uint256 indexed value);
    event UpdatedGatewayManager(address indexed oldAddr, address indexed newAddr);
    event RecordhashChanged(address indexed owner, bytes32 indexed node, bytes contenthash);
    event OwnerhashChanged(address indexed owner, bytes contenthash);
    event UpdatedWrapper(address indexed newAddr, bool indexed status);
    event ApprovedSigner(address owner, bytes32 indexed node, address indexed delegate, bool indexed approved);
    event UpdatedSupportedInterface(bytes4 indexed sig, bool indexed status);

    /// Errors
    error InvalidSignature(string message);

    /// @dev - ENS Legacy Registry
    iENS public immutable ENS = iENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);
    /// @dev - CCIP-Read Gateways
    iGatewayManager public gateway;
    /// @dev - Deployed Chain ID
    string chainID;

    /// Mappings
    /**
     * @dev - Domain-specific contenthash storing all other records
     * @notice - Should be in generic ENS contenthash format or base32/base36 string URL format
     */
    mapping(bytes32 => bytes) public recordhash;
    /// @dev - Owner-specific contenthash storing records for all names owned by a wallet
    mapping(bytes32 => bytes) public ownerhash;
    /// @dev - On-chain singular Manager database
    /// Note - Manager (= isApprovedSigner) is someone who can manage off-chain records for a domain on behalf of its owner
    mapping(address => mapping(bytes32 => mapping(address => bool))) public isApprovedSigner;
    /// @dev - List of all wrapping contracts to be declared in contructor
    mapping(address => bool) public isWrapper;

    /// Interfaces
    mapping(bytes4 => bool) public supportsInterface;

    /// @dev - Constructor
    constructor(address _gateway, string memory _chainID) {
        gateway = iGatewayManager(_gateway);
        chainID = _chainID;
        /// @dev - Sets ENS Mainnet wrapper as Wrapper
        isWrapper[0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401] = true;
        emit UpdatedWrapper(0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401, true);

        /// @dev - Set necessary interfaces
        supportsInterface[iERC165.supportsInterface.selector] = true;
        supportsInterface[iENSIP10.resolve.selector] = true;
        supportsInterface[type(iERC173).interfaceId] = true;
        supportsInterface[iCCIP2ETH.setRecordhash.selector] = true;
    }

    /**
     * @dev Set new Gateway Manager Contract
     * @param _gateway - Address of new Gateway Manager Contract
     */
    function updateGatewayManager(address _gateway) external {
        require(msg.sender == gateway.owner(), "ONLY_DEV");
        require(msg.sender == iGatewayManager(_gateway).owner(), "BAD_GATEWAY");
        emit UpdatedGatewayManager(address(gateway), _gateway);
        gateway = iGatewayManager(_gateway);
    }

    /**
     * @dev Sets recordhash for a node
     * Note - Only ENS owner or manager of node can call
     * @param _node - Namehash of domain.eth
     * @param _contenthash - Contenthash to set as recordhash
     */
    function setRecordhash(bytes32 _node, bytes calldata _contenthash) external {
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        require(msg.sender == _owner || isApprovedSigner[_owner][_node][msg.sender], "NOT_AUTHORIZED");
        recordhash[_node] = _contenthash;
        emit RecordhashChanged(msg.sender, _node, _contenthash);
    }

    /**
     * @dev Sets ownerhash for an owner
     * Note - Wallet-specific fallback recordhash
     * @param _contenthash - Contenthash to set as ownerhash
     */
    function setOwnerhash(bytes calldata _contenthash) external {
        ownerhash[keccak256(abi.encodePacked(msg.sender))] = _contenthash;
        emit OwnerhashChanged(msg.sender, _contenthash);
    }

    /**
     * @dev Sets recordhash for a subnode
     * Note - Only ENS owner or manager of parent node can call
     * @param _subdomain - Subdomain labels; a.b.c.domain.eth = [a, b, c]
     * @param _node - Namehash of domain.eth
     * @param _contenthash - Contenthash to set as recordhash
     */
    function setSubRecordhash(string[] calldata _subdomain, bytes32 _node, bytes calldata _contenthash) external {
        bytes32 _namehash = _node;
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        require(msg.sender == _owner || isApprovedSigner[_owner][_node][msg.sender], "NOT_AUTHORIZED");
        uint256 len = _subdomain.length;
        unchecked {
            while (len > 0) {
                _namehash = keccak256(abi.encodePacked(_namehash, keccak256(bytes(_subdomain[--len]))));
            }
        }
        recordhash[_namehash] = _contenthash;
        emit RecordhashChanged(msg.sender, _namehash, _contenthash);
    }

    /**
     * @dev EIP-2544/EIP-3668 core resolve() function; aka CCIP-Read
     * @param name - ENS domain to resolve; must be DNS encoded
     * @param request - Encoding-specific function to resolve
     * @return result - Triggers Off-chain Lookup
     * Note - Return value is not used
     */
    function resolve(bytes calldata name, bytes calldata request) external view returns (bytes memory) {
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
            bytes32 _namehash = keccak256(abi.encodePacked(bytes32(0), keccak256(_labels[--index])));
            bytes32 _node;
            bytes memory _recordhash;
            // Calculate 'closest-set' parent node
            while (index > 0) {
                _namehash = keccak256(abi.encodePacked(_namehash, keccak256(_labels[--index])));
                // Check if sub(domain) exists on-chain or off-chain
                if (ENS.recordExists(_namehash) || bytes(recordhash[_namehash]).length > 0) {
                    _node = _namehash;
                    _recordhash = recordhash[_namehash];
                }
            }
            address _owner = ENS.owner(_node);         
            // Update ownership if domain is wrapped
            if (isWrapper[_owner]) {
                _owner = iToken(_owner).ownerOf(uint256(_node));
            }
            if (_recordhash.length == 0) {
                // Check if recordhash exists
                bytes32 _addrhash = keccak256(abi.encodePacked(_owner));
                if (ownerhash[_addrhash].length == 0) {
                    // Check if ownerhash exists, if no recordhash is found
                    revert("RECORD_NOT_SET");
                }
                _recordhash = ownerhash[_addrhash]; // Fallback to ownerhash in absence of recordhash
            }
            string memory _recType = gateway.funcToJson(request); // Filename for the requested record
            bytes32 _checkHash = keccak256(
                abi.encodePacked(this, blockhash(block.number - 1), _owner, _domain, _path, request, _recType)
            );
            revert OffchainLookup(
                address(this), // Callback contract (= THIS, for this case)
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _recType), uint256(_checkHash)
                ), // Generate pseudo-random list of gateways for record resolution
                abi.encodePacked(uint16(block.timestamp / 60)), // Cache = 60 seconds
                iCCIP2ETH.__callback.selector, // Callback function
                abi.encode(_node, block.number - 1, _namehash, _checkHash, _domain, _path, request)
            );
        }
    }

    /**
     * @dev Redirects the CCIP-Read request to another ENS Domain
     * @param _encoded - ENS domain to resolve; must be DNS encoded
     * @param _requested - Originally requested encoding-specific function to resolve
     * @return _selector - Redirected function selector
     * @return _namehash - Redirected namehash
     * @return _redirectRequest - Redirected request
     * @return domain - String-formatted ENS domain
     */
    function redirectService(bytes calldata _encoded, bytes calldata _requested)
        external
        view
        returns (bytes4 _selector, bytes32 _namehash, bytes memory _redirectRequest, string memory domain)
    {
        uint256 index = 1;
        uint256 n = 1;
        uint256 len = uint8(bytes1(_encoded[:1]));
        bytes[] memory _labels = new bytes[](42);
        _labels[0] = _encoded[1:n += len];
        domain = string(_labels[0]);
        while (_encoded[n] > 0x0) {
            len = uint8(bytes1(_encoded[n:++n]));
            _labels[index] = _encoded[n:n += len];
            domain = string.concat(domain, ".", string(_labels[index]));
        }
        bytes32 _owned;
        _namehash = keccak256(abi.encodePacked(bytes32(0), keccak256(_labels[--index])));
        while (index > 0) {
            _namehash = keccak256(abi.encodePacked(_namehash, keccak256(_labels[--index])));
            if (ENS.recordExists(_namehash)) {
                _owned = _namehash;
            }
        }
        require(_owned != bytes32(0), "NOT_REGISTERED");
        _selector = bytes4(_requested[:4]);
        _redirectRequest = abi.encodePacked(_selector, _namehash, _requested.length > 36 ? _requested[36:] : bytes(""));
        _namehash = _owned;
    }

    /**
     * @dev Checks for manager access to an ENS domain for record management
     * @param _owner - Owner of ENS domain
     * @param _approvedSigner - Manager address to check
     * @param _node - Namehash of ENS domain
     * @param _signature - Signature to verify
     * @param _domain - String-formatted ENS domain
     * @return  - Whether manager is approved by the owner
     */
    function approvedSigner(
        address _owner,
        address _approvedSigner,
        bytes32 _node,
        bytes memory _signature,
        string memory _domain
    ) public view returns (bool) {
        address _Signer = iCCIP2ETH(this).getSigner(
            string.concat(
                "Requesting Signature To Approve ENS Records Signer\n",
                "\nENS Domain: ",
                _domain,
                "\nApproved Signer: eip155:",
                chainID,
                ":",
                gateway.toChecksumAddress(_approvedSigner),
                "\nExtradata: 0x",
                gateway.bytes32ToHexString(keccak256(abi.encodePacked(_owner, _approvedSigner))),
                "\nSigned By: eip155:",
                chainID,
                ":",
                gateway.toChecksumAddress(_owner)
            ),
            _signature
        );
        return (_Signer == _owner || isApprovedSigner[_owner][_node][_Signer]);
    }

    /**
     * @dev Default Callback function
     * @param response - Response of CCIP-Read call
     * @param extradata - Extra data used by callback
     * @return result - Concludes Off-chain Lookup
     * Note - Return value is not used
     */
    function __callback(bytes calldata response, bytes calldata extradata)
        external
        view
        returns (bytes memory result)
    {
        (
            bytes32 _node, // Namehash of ENS domain
            uint256 _blocknumber,
            bytes32 _namehash, // Namehash of node with recordhash
            bytes32 _checkHash, // Extra checkhash
            string memory _domain, // String-formatted complete 'a.b.c.domain.eth'
            string memory _path, // Reverse DNS path 'eth/domain/c/b/a'
            bytes memory _request // Format: <bytes4> + <namehash> + <extradata>
        ) = abi.decode(extradata, (bytes32, uint256, bytes32, bytes32, string, string, bytes));
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        string memory _recType = gateway.funcToJson(_request);
        /// @dev - Timeout in 4 blocks
        require(
            block.number < _blocknumber + 5
                && _checkHash
                    == keccak256(abi.encodePacked(this, blockhash(_blocknumber), _owner, _domain, _path, _request, _recType)),
            "INVALID_CHECKSUM/TIMEOUT"
        );
        // Signer could be:
        // a) Owner
        // OR, b) On-chain approved manager
        // OR, c) Off-chain approved signer
        address _signer;
        /// Signature associated with the record
        bytes memory _recordSignature;
        /// Init off-chain manager's signature request
        string memory signRequest;
        /// Get signer-type from response identifier
        bytes4 _type = bytes4(response[:4]);
        /// Off-chain signature approving record signer (if signer != owner or on-chain manager)
        bytes memory _approvedSig;
        /// @dev CCIP Response Decode
        (_signer, _recordSignature, _approvedSig, result) = abi.decode(response[4:], (address, bytes, bytes, bytes));
        if (_approvedSig.length < 64) {
            require(_signer == _owner || isApprovedSigner[_owner][_node][_signer], "INVALID_CALLBACK");
        } else {
            require(approvedSigner(_owner, _signer, _node, _approvedSig, _domain), "BAD_RECORD_APPROVAL");
        }
        if (_type == iCallbackType.signedRecord.selector) {
            /// @dev If 'signedRecord()' bytes4 selector; handles signed records
            signRequest = string.concat(
                "Requesting Signature To Update ENS Record\n",
                "\nENS Domain: ",
                _domain,
                "\nRecord Type: ",
                _recType,
                "\nExtradata: 0x",
                gateway.bytesToHexString(abi.encodePacked(keccak256(result)), 0),
                "\nSigned By: eip155:",
                chainID,
                ":",
                gateway.toChecksumAddress(_signer)
            );
            require(_signer == iCCIP2ETH(this).getSigner(signRequest, _recordSignature), "BAD_SIGNED_RECORD");
        } else if (_type == iCallbackType.signedRedirect.selector) {
            /// @dev If 'signedRedirect()' bytes4 selector; handles redirected records
            if (result[0] == 0x0) {
                signRequest = string.concat(
                    "Requesting Signature To Redirect ENS Records\n",
                    "\nENS Domain: ",
                    _domain, // <app>.domain.eth
                    "\nExtradata: 0x",
                    gateway.bytesToHexString(abi.encodePacked(keccak256(result)), 0),
                    "\nSigned By: eip155:",
                    chainID,
                    ":",
                    gateway.toChecksumAddress(_signer)
                );
                require(_signer == iCCIP2ETH(this).getSigner(signRequest, _recordSignature), "BAD_DAPP_SIGNATURE");
                // Signed IPFS redirect
                revert OffchainLookup(
                    address(this),
                    gateway.randomGateways(
                        abi.decode(result, (bytes)), // ABI-decode as recordhash to redirect
                        string.concat("/.well-known/", _path, "/", _recType),
                        uint256(_checkHash)
                    ),
                    abi.encodePacked(uint16(block.timestamp / 60)),
                    gateway.__fallback.selector, // Fallback; 2nd Callback
                    abi.encode(_node, block.number - 1, _namehash, _checkHash, _domain, _path, _request)
                );
            }
            // ENS dApp redirect
            // Result should be DNS encoded; result should NOT be ABI-encoded
            // Note Last byte is 0x00, meaning end of DNS-encoded stream
            require(result[result.length - 1] == 0x0, "BAD_ENS_ENCODED");
            (bytes4 _sig, bytes32 _redirectNamehash, bytes memory _redirectRequest, string memory _redirectDomain) =
                CCIP2ETH(this).redirectService(result, _request);
            signRequest = string.concat(
                "Requesting Signature To Install dApp Service\n",
                "\nENS Domain: ",
                _domain, // e.g. ens.domain.eth
                "\ndApp: ",
                _redirectDomain, // e.g. app.ens.eth
                "\nExtradata: 0x",
                gateway.bytesToHexString(abi.encodePacked(keccak256(result)), 0),
                "\nSigned By: eip155:",
                chainID,
                ":",
                gateway.toChecksumAddress(_signer)
            );
            require(_signer == iCCIP2ETH(this).getSigner(signRequest, _recordSignature), "BAD_DAPP_SIGNATURE");
            address _resolver = ENS.resolver(_redirectNamehash); // Owned node
            if (iERC165(_resolver).supportsInterface(iENSIP10.resolve.selector)) {
                return iENSIP10(_resolver).resolve(result, _redirectRequest);
            } else if (iERC165(_resolver).supportsInterface(_sig)) {
                bool ok;
                (ok, result) = _resolver.staticcall(_redirectRequest);
                require(ok, "BAD_RESOLVER_TYPE");
                require(result.length > 32 || bytes32(result) > bytes32(0), "RECORD_NOT_SET");
            } else {
                revert("BAD_RESOLVER_FUNCTION");
            }
        } else {
            /// @dev Future features in __fallback
            _namehash;
            return gateway.__fallback(response, extradata);
        }
    }

    /**
     * @dev Checks if a signature is valid
     * @param signRequest - String-formatted message that was signed
     * @param signature - Compact signature to verify
     * @return signer - Signer of message
     * @notice - Signature Format:
     * a) 64 bytes - bytes32(r) + bytes32(vs) ~ compact, or
     * b) 65 bytes - bytes32(r) + bytes32(s) + uint8(v) ~ packed, or
     * c) 96 bytes - bytes32(r) + bytes32(s) + uint256(v) ~ longest
     */
    function getSigner(string calldata signRequest, bytes calldata signature) external view returns (address signer) {
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
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n", gateway.uintToString(bytes(signRequest).length), signRequest
            )
        );
        signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "ZERO_ADDR");
    }

    /**
     * @dev Sets a signer (= manager) as approved to manage records for a node
     * @param _node - Namehash of ENS domain
     * @param _signer - Address of signer (= manager)
     * @param _approval - Status to set
     */
    function approve(bytes32 _node, address _signer, bool _approval) external {
        isApprovedSigner[msg.sender][_node][_signer] = _approval;
        emit ApprovedSigner(msg.sender, _node, _signer, _approval);
    }

    /**
     * @dev Sets multiple signer (= manager) as approved to manage records for a node
     * @param _node - Namehash of ENS domain
     * @param _signer - Address of signer (= manager)
     * @param _approval - Status to set
     */
    function multiApprove(bytes32[] calldata _node, address[] calldata _signer, bool[] calldata _approval) external {
        uint256 len = _node.length;
        require(len == _signer.length, "BAD_LENGTH");
        require(len == _approval.length, "BAD_LENGTH");
        for (uint256 i = 0; i < len; i++) {
            isApprovedSigner[msg.sender][_node[i]][_signer[i]] = _approval[i];
            emit ApprovedSigner(msg.sender, _node[i], _signer[i], _approval[i]);
        }
    }

    /**
     * @dev Checks if a signer (= manager) is approved to manage records for a node
     * @param _node - Namehash of ENS domain
     * @param _signer - Address of signer (= manager)
     */
    function approved(bytes32 _node, address _signer) public view returns (bool) {
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        return _owner == _signer || isApprovedSigner[_owner][_node][_signer];
    }

    /**
     * @dev Updates supported interfaces
     * @param _sig - 4-byte interface selector
     * @param _set - State to set for selector
     */
    function updateSupportedInterface(bytes4 _sig, bool _set) external {
        require(msg.sender == gateway.owner(), "ONLY_DEV");
        supportsInterface[_sig] = _set;
        emit UpdatedSupportedInterface(_sig, _set);
    }

    /**
     * @dev Add or remove ENS wrapper
     * @param _addr - Address of ENS wrapper
     * @param _set - State to set for new ENS wrapper
     */
    function updateWrapper(address _addr, bool _set) external {
        require(msg.sender == gateway.owner(), "ONLY_DEV");
        require(!_set || _addr.code.length > 0, "ONLY_CONTRACT");
        isWrapper[_addr] = _set;
        emit UpdatedWrapper(_addr, _set);
    }

    /**
     * @dev - Owner of contract
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
     * @param _tokenContract - Token contract address
     * @param _balance - Amount to release
     */
    function withdraw(address _tokenContract, uint256 _balance) external {
        iToken(_tokenContract).transferFrom(address(this), gateway.owner(), _balance);
    }

    /**
     * @dev To be used for tips or in case some non-fungible tokens get locked in the contract
     * @param _tokenContract - Token contract address
     * @param _tokenID - Token ID to release
     */
    function safeWithdraw(address _tokenContract, uint256 _tokenID) external {
        iToken(_tokenContract).safeTransferFrom(address(this), gateway.owner(), _tokenID);
    }
}
