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
    event GatewayUpdated(address indexed oldAddr, address indexed newAddr);
    event RecordhashUpdated(address indexed owner, bytes32 indexed node, bytes contenthash);
    event OwnerhashChanged(address indexed owner, bytes contenthash);
    event UpdatedWrapper(address indexed newAddr, bool indexed status);
    event ApprovedSigner(address owner, bytes32 indexed node, address indexed delegate, bool indexed approved);
    event InterfaceUpdated(bytes4 indexed sig, bool indexed status);

    /// Errors
    error InvalidSignature(string message);
    error InvalidRequest(string message);
    error NotAuthorized();
    /// @dev - ENS Legacy Registry
    iENS public immutable ENS = iENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);
    /// @dev - CCIP-Read Gateways
    iGatewayManager public gateway;

    /// Mappings
    /**
     * @dev - Domain-specific contenthash storing all other records
     * @notice - Should be in generic ENS contenthash format or base32/base36 string URL format
     */
    mapping(bytes32 => bytes) public recordhash;
    /// @dev - On-chain singular Manager database
    /// Note - Manager (= isApprovedSigner) is someone who can manage off-chain records for a domain on behalf of its owner
    mapping(address => mapping(bytes32 => mapping(address => bool))) public isApprovedSigner;
    /// @dev - List of all wrapping contracts to be declared in contructor
    mapping(address => bool) public isWrapper;

    /// Interfaces
    mapping(bytes4 => bool) public supportsInterface;

    /// @dev - Constructor
    constructor(address _gateway) {
        gateway = iGatewayManager(_gateway);

        /// @dev - Sets ENS Mainnet wrapper contract
        isWrapper[0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401] = true;
        emit UpdatedWrapper(0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401, true);

        /// @dev - Sets ENS TESTNET wrapper contract
        isWrapper[0x0000000000000000000000000000000000000000] = true;
        emit UpdatedWrapper(0x0000000000000000000000000000000000000000, true);

        /// @dev - Set necessary interfaces
        supportsInterface[iERC165.supportsInterface.selector] = true;
        supportsInterface[iENSIP10.resolve.selector] = true;
        supportsInterface[type(iERC173).interfaceId] = true;
        supportsInterface[iCCIP2ETH.setRecordhash.selector] = true;
        supportsInterface[iCallbackType.signedRecord.selector] = true;
        supportsInterface[iCallbackType.signedDAppService.selector] = true;
    }

    function updateGatewayManager(address _gateway) external {
        require(msg.sender == gateway.owner(), "ONLY_DEV");
        require(msg.sender == iGatewayManager(_gateway).owner(), "BAD_GATEWAY");
        emit GatewayUpdated(address(gateway), _gateway);
        gateway = iGatewayManager(_gateway);
    }

    /**
     * @dev Sets recordhash for a node
     * Note - Only ENS owner or manager of node can call
     * @param _node - Namehash of domain.eth
     * @param _recordhash - Contenthash to set as recordhash
     */
    function setRecordhash(bytes32 _node, bytes calldata _recordhash) external {
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        if(msg.sender != _owner && !isApprovedSigner[_owner][_node][msg.sender]){
            revert NotAuthorized();
        }
        recordhash[_node] = _recordhash;
        emit RecordhashUpdated(msg.sender, _node, _recordhash);
    }

    /**
     * @dev Sets recordhash for a node
     * Note - Only ENS owner or manager of node can call
     * Note - Bytes32, ed25519 suffix hash only
     * @param _node - Namehash of domain.eth
     * @param _recordhash - IPNS Contenthash to set as recordhash 
     */
    function setRecordhash(bytes32 _node, bytes32 _recordhash) external {
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        if(msg.sender != _owner && !isApprovedSigner[_owner][_node][msg.sender]){
            revert NotAuthorized();
        }
        recordhash[_node] = abi.encodePacked(_recordhash);
        emit RecordhashUpdated(msg.sender, _node, abi.encodePacked(hex"e5010172002408011220", _recordhash));
    }


    /**
     * @dev Sets ownerhash for an owner
     * Note - Wallet-specific fallback recordhash
     * @param _recordhash - Contenthash to set as ownerhash
     */
    function setOwnerhash(bytes calldata _recordhash) external payable {
        require(msg.value >= ownerhashFees, "PLS_FUND_DEVS");
        recordhash[keccak256(abi.encodePacked(msg.sender))] = _recordhash;
        emit RecordhashUpdated(msg.sender, bytes32(type(uint256).max), _recordhash);
    }

    /**
     * @dev Sets Deep recordhash for a sub/subnode
     * Note - Only ENS owner or manager of parent node can call
     * @param _node - Namehash of domain.eth
     * @param _subdomain - Subdomain labels; a.b.c.domain.eth = [a, b, c]
     * @param _recordhash - Contenthash to set as recordhash
     */
    function setDeepSubRecordhash(bytes32 _node, string[] calldata _subdomain, bytes calldata _recordhash) external {
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
        recordhash[_namehash] = _recordhash;
        emit RecordhashUpdated(msg.sender, _namehash, _recordhash);
    }

    /**
     * @dev Sets recordhash for a subnode
     * Note - Only ENS owner or manager of parent node can call
     * @param _node - Namehash of domain.eth
     * @param _subdomain - Subdomain labels; a.domain.eth = "a"
     * @param _recordhash - Contenthash to set as recordhash
     */
    function setSubRecordhash(bytes32 _node, string calldata _subdomain, bytes calldata _recordhash) external {
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        require(msg.sender == _owner || isApprovedSigner[_owner][_node][msg.sender], "NOT_AUTHORIZED");
        bytes32 _namehash = keccak256(abi.encodePacked(_node, keccak256(bytes(_subdomain))));
        recordhash[_namehash] = _recordhash;
        emit RecordhashUpdated(msg.sender, _namehash, _recordhash);
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
            uint256 len = uint8(bytes1(name[0]));
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
            while (index > 0) {
                _namehash = keccak256(abi.encodePacked(_namehash, keccak256(_labels[--index])));
                if (ENS.recordExists(_namehash)) {
                    _node = _namehash;
                    _recordhash = recordhash[_namehash];
                } else if (bytes(recordhash[_namehash]).length > 0) {
                    _recordhash = recordhash[_namehash];
                }
            }
            address _owner = ENS.owner(_node);
            if (isWrapper[_owner]) {
                _owner = iToken(_owner).ownerOf(uint256(_node));
            }
            if (_recordhash.length == 0) {
                _recordhash = recordhash[keccak256(abi.encodePacked(_owner))];
                if (_recordhash.length == 0) {
                    revert InvalidRequest("RECORD_NOT_SET");
                }
            }
            string memory _recType = gateway.funcToJson(request);
            bytes32 _checkHash = keccak256(
                abi.encodePacked(this, blockhash(block.number - 1), _owner, _domain, request, _recType)
            );
            revert OffchainLookup(
                address(this),
                gateway.randomGateways(
                    _recordhash, string.concat("/.well-known/", _path, "/", _recType), uint256(_checkHash)
                ),
                abi.encodePacked(uint16(block.timestamp / 60)),
                iCCIP2ETH.__callback.selector,
                abi.encode(_node, block.number - 1, _checkHash, _domain, name, _recType, request)
            );
        }
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
        bytes4 _type = bytes4(response[:4]);
        if (!supportsInterface[_type]) {
            /// @dev Future features in __fallback
            return gateway.__fallback(response, extradata);
        }
        (
            bytes32 _node, // Namehash of base owned ENS domain
            uint256 _blocknumber,
            bytes32 _checkHash, // Extra checkhash
            string memory _domain, // String-formatted complete 'a.b.c.domain.eth'
            ,//bytes memory _name, // DNS encoded domain.eth
            string memory _recType, // record type
            bytes memory _request // Format: <bytes4> + <namehash> + <extradata>
        ) = abi.decode(extradata, (bytes32, uint256, bytes32, string, bytes, string, bytes));
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        //string memory _recType = gateway.funcToJson(_request);
        /// @dev - Timeout in 4 blocks
        if (block.number > _blocknumber + 4) {
            revert InvalidRequest("CHECK_TIMEOUT");
        }
        if (
            _checkHash
                != keccak256(abi.encodePacked(this, blockhash(_blocknumber), _owner, _domain, _request, _recType))
        ) {
            revert InvalidRequest("BAD_CHECKSUM");
        }
        address _signer;
        bytes memory _recordSignature;
        bytes memory _approvedSig;
        (_signer, _recordSignature, _approvedSig, result) = abi.decode(response[4:], (address, bytes, bytes, bytes));
        if (_approvedSig.length < 64) {
            if (_signer != _owner && !isApprovedSigner[_owner][_node][_signer]) {
                revert InvalidRequest("NOT_AUTHORIZED");
            }
        } else if (!approvedSigner(_owner, _signer, _node, _approvedSig, _domain)) {
            revert InvalidRequest("NOT_APPROVED");
        }
        string memory signRequest;
        if (_type == iCallbackType.signedRecord.selector) {
            signRequest = string.concat(
                "Requesting Signature To Update ENS Record\n",
                "\nOrigin: ",
                _domain,
                "\nRecord Type: ",
                _recType,
                "\nExtradata: 0x",
                gateway.bytesToHexString(abi.encodePacked(keccak256(result)), 0),
                "\nSigned By: eip155:1:",
                gateway.toChecksumAddress(_signer)
            );
            if (_signer != iCCIP2ETH(this).getSigner(signRequest, _recordSignature)) {
                revert InvalidRequest("BAD_SIGNED_RECORD");
            }
        } else if (_type == iCallbackType.signedDAppService.selector) {
            if (result[0] == 0x0 || result[result.length - 1] != 0x0) {
                revert InvalidRequest("BAD_DAPP_SERVICE_REQUEST");
            }
            (bytes4 _req, bytes32 _redirectNamehash, bytes memory _redirectRequest, string memory _redirectDomain) =
                iCCIP2ETH(this).redirectService(result, _request);
            signRequest = string.concat(
                "Requesting Signature To Install DApp Service\n",
                "\nOrigin: ",
                _domain, // e.g. ens.domain.eth
                "\nDApp: ",
                _redirectDomain, // e.g. app.ens.eth
                "\nExtradata: 0x",
                gateway.bytesToHexString(abi.encodePacked(keccak256(result)), 0),
                "\nSigned By: eip155:1:",
                gateway.toChecksumAddress(_signer)
            );
            if (_signer != iCCIP2ETH(this).getSigner(signRequest, _recordSignature)) {
                revert InvalidRequest("BAD_DAPP_SIGNATURE");
            }
            address _resolver = ENS.resolver(_redirectNamehash);
            if (iERC165(_resolver).supportsInterface(iENSIP10.resolve.selector)) {
                return iENSIP10(_resolver).resolve(result, _redirectRequest);
            } else if (iERC165(_resolver).supportsInterface(_req)) {
                bool ok;
                (ok, result) = _resolver.staticcall(_redirectRequest);
                if (!ok) {
                    revert InvalidRequest("BAD_RESOLVER");
                }
            } else {
                revert InvalidRequest("BAD_RESOLVER_FUNCTION");
            }
        } else {
            /// @dev Future features in __fallback
            return gateway.__fallback(response, extradata);
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
        uint256 len = uint8(bytes1(_encoded[0]));
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
        if (_owned == bytes32(0)) {
            revert InvalidRequest("NOT_REGISTERED");
        }
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
        address _signer = iCCIP2ETH(this).getSigner(
            string.concat(
                "Requesting Signature To Approve Offchain ENS Records Signer\n",
                "\nOrigin: ",
                _domain,
                "\nApproved Signer: eip155:1:",
                gateway.toChecksumAddress(_approvedSigner),
                "\nApproved By: eip155:1:",
                gateway.toChecksumAddress(_owner)
            ),
            _signature
        );
        return (_signer == _owner || isApprovedSigner[_owner][_node][_signer]);
    }
    
    /**
     * @dev Checks if a signature is valid
     * @param _message - String-formatted message that was signed
     * @param _signature - Compact signature to verify
     * @return _signer - Signer of message
     * @notice Signature Format:
     * a) 64 bytes - bytes32(r) + bytes32(vs) ~ compact, or
     * b) 65 bytes - bytes32(r) + bytes32(s) + uint8(v) ~ packed, or
     * c) 96 bytes - bytes32(r) + bytes32(s) + uint256(v) ~ longest
     */
    function getSigner(string calldata _message, bytes calldata _signature) external view returns (address _signer) {
        bytes32 r = bytes32(_signature[:32]);
        bytes32 s;
        uint8 v;
        uint256 len = _signature.length;
        if (len == 64) {
            bytes32 vs = bytes32(_signature[32:]);
            s = vs & bytes32(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
            v = uint8((uint256(vs) >> 255) + 27);
        } else if (len == 65) {
            s = bytes32(_signature[32:64]);
            v = uint8(bytes1(_signature[64:]));
        } else if (len == 96) {
            s = bytes32(_signature[32:64]);
            v = uint8(uint256(bytes32(_signature[64:])));
        } else {
            revert InvalidSignature("BAD_SIG_LENGTH");
        }
        if (s > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert InvalidSignature("INVALID_S_VALUE");
        }
        bytes32 digest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n", gateway.uintToString(bytes(_message).length), _message)
        );
        _signer = ecrecover(digest, v, r, s);
        if (_signer == address(0)) {
            revert InvalidSignature("ZERO_ADDR");
        }
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

    /// @dev : management functions

    modifier OnlyDev() {
        require(msg.sender == gateway.owner(), "ONLY_DEV");
        _;
    }

    uint256 public ownerhashFees = 0; // start fees at 0
    /**
     * @dev Set fees for oewnerhash
     * Note : It's free @ 0, might need this in future for dev funding
     * @param _wei - Fees in WEI per EOA
     */

    function updateOwnerhashFees(uint256 _wei) external OnlyDev {
        ownerhashFees = _wei;
    }

    /**
     * @dev Set new Gateway Manager Contract
     * @param _gateway - Address of new Gateway Manager Contract
     */
    function updateGateway(address _gateway) external OnlyDev {
        require(_gateway.code.length > 0, "ONLY_CONTRACT");
        require(msg.sender == iGatewayManager(_gateway).owner(), "BAD_GATEWAY_OWNER");
        emit GatewayUpdated(address(gateway), _gateway);
        gateway = iGatewayManager(_gateway);
    }

    /**
     * @dev Updates supported interfaces
     * @param _sig - 4-byte interface selector
     * @param _set - State to set for selector
     */
    function updateInterface(bytes4 _sig, bool _set) external OnlyDev {
        require(_sig != iCallbackType.signedRecord.selector, "LOCKED_CALLBACK_TYPE");
        require(_sig != iENSIP10.resolve.selector, "LOCKED_CALLBACK_TYPE");
        supportsInterface[_sig] = _set;
        emit InterfaceUpdated(_sig, _set);
    }

    /**
     * @dev Add or remove ENS wrapper
     * @param _addr - Address of ENS wrapper
     * @param _set - State to set for new ENS wrapper
     */
    function updateWrapper(address _addr, bool _set) external OnlyDev {
        require(_addr.code.length > 0, "ONLY_CONTRACT");
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
     * @param _contract - Token contract address
     * @param _balance - Amount to release
     */
    function withdraw(address _contract, uint256 _balance) external {
        iToken(_contract).transferFrom(address(this), gateway.owner(), _balance);
    }

    /**
     * @dev To be used for tips or in case some non-fungible tokens get locked in the contract
     * @param _contract - Token contract address
     * @param _token - Token ID to release
     */
    function safeWithdraw(address _contract, uint256 _token) external {
        iToken(_contract).safeTransferFrom(address(this), gateway.owner(), _token);
    }
}
