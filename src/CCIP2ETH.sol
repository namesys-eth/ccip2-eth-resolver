// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

import "./Interface.sol";
//import "forge-std/Test.sol";

/**
 * @title Off-Chain ENS Records Manager
 * @author freetib.eth, sshmatrix.eth
 * Github : https://github.com/namesys-eth/ccip2-eth-resolver
 * Client : https://namesys.eth.limo
 */
contract CCIP2ETH is iCCIP2ETH {
    /// @dev - ONLY TESTNET
    /// TODO - Remove before Mainnet deployment
    function immolate() external {
        address _owner = gateway.owner();
        require(msg.sender == _owner, "NOT_OWNER");
        selfdestruct(payable(_owner));
    }

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
    event UpdateGatewayManager(address indexed oldAddr, address indexed newAddr);
    event RecordhashChanged(address indexed owner, bytes32 indexed node, bytes contenthash);
    event MasterhashChanged(address indexed wallet, bytes masterhash);
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
    /**
     * @dev - Domain-specific contenthash storing all other records
     * @notice - Should be in generic ENS contenthash format or base32/base36 string URL format
     */
    mapping(bytes32 => bytes) public recordhash;
    /// @dev - Wallet-specific contenthash storing records for all names owned by a wallet
    mapping(address => bytes) public masterhash;
    /// @dev - On-chain singular Manager database
    /// Note - Manager (= isApprovedSigner) is someone who can manage off-chain records for a domain on behalf of its owner
    mapping(address => mapping(bytes32 => mapping(address => bool))) public isApprovedSigner;
    //mapping(bytes32 => bool) public manager;
    /// @dev - List of all wrapping contracts to be declared in contructor
    mapping(address => bool) public isWrapper;

    /// Interfaces
    mapping(bytes4 => bool) public supportsInterface;

    /// @dev - Constructor
    constructor(address _gateway) {
        gateway = iGatewayManager(_gateway);

        /// @dev - Sets ENS Mainnet wrapper as Wrapper
        isWrapper[0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401] = true;
        emit UpdateWrapper(0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401, true);

        /// @dev - Sets ENS Goerli wrapper as Wrapper; remove before Mainnet deploy [?TODO]
        //isWrapper[0x114D4603199df73e7D157787f8778E21fCd13066] = true;
        //emit UpdateWrapper(0x114D4603199df73e7D157787f8778E21fCd13066, true);

        /// @dev - Set necessary interfaces
        supportsInterface[iERC165.supportsInterface.selector] = true;
        supportsInterface[iENSIP10.resolve.selector] = true;
        supportsInterface[type(iERC173).interfaceId] = true;
        supportsInterface[iCCIP2ETH.recordhash.selector] = true;
        supportsInterface[iCCIP2ETH.setRecordhash.selector] = true;
    }

    /**
     * @dev Checks if a manager is authorised by the owner of ENS domain
     * @param _node - Namehash of ENS domain
     * @param _owner - Owner of ENS domain
     * @param _manager - Manager address to check
     */
    function isAuthorized(bytes32 _node, address _owner, address _manager) public view returns (bool) {
        return (isApprovedSigner[_owner][_node][_manager] || ENS.isApprovedForAll(_owner, _manager));
    }

    /**
     * @dev Set new Gateway Manager Contract
     * @param _gateway - Address of new Gateway Manager Contract
     */
    function updateGatewayManager(address _gateway) external {
        require(msg.sender == gateway.owner(), "ONLY_DEV");
        require(msg.sender == iGatewayManager(_gateway).owner(), "BAD_GATEWAY");
        emit UpdateGatewayManager(address(gateway), _gateway);
        gateway = iGatewayManager(_gateway);
    }

    /**
     * @dev Slices and returns all except first N bytes
     * @param _bytes - Bytes to slice
     * @param _index - Index to start slicing at
     * @return - Returns sliced bytes
     */
    function selectBytes(bytes memory _bytes, uint256 _index) public pure returns (bytes memory) {
        bytes memory __bytes = new bytes(_bytes.length - 1);
        for (uint256 i = _index; i < _bytes.length; i++) {
            __bytes[i - _index] = _bytes[i];
        }
        return __bytes;
    }

    /**
     * @dev Sorts the priority order when both masterhash and recordhash exist
     * @param _node - Namehash of ENS domain
     * @param _owner - Owner of ENS domain
     * @return - Returns masterhash or recordhash according to priority rules
     */
    function breakParity(bytes32 _node, address _owner) public view returns (bytes memory, bytes1) {
        // Set default priority to recordhash
        bytes memory _toReturn = recordhash[_node];
        bytes1 _flag = bytes1(0x00);
        // Check if recordhash exists
        if (_toReturn.length > 0) {
            // Check if masterhash also exists
            if (masterhash[_owner].length > 0) {
                if (uint8(masterhash[_owner][0]) > 0) {
                    // Prioritize masterhash otherwise
                    // Note: Must strip first byte before returning value and append identifier
                    _toReturn = selectBytes(masterhash[_owner], 1);
                    _flag = bytes1(0x01);
                }
            }
        } else if (masterhash[_owner].length > 0) {
            // Use masterhash only if no recordhash exists
            // Note: Identifier for masterhash is appended
            _toReturn = selectBytes(masterhash[_owner], 1);
            _flag = bytes1(0x01);
        }
        return (_toReturn, _flag);
    }

    /**
     * @dev Sets recordhash for a node
     * Note - Only ENS owner or manager can call
     * @param _node - Namehash of ENS domain
     * @param _recordhash - Contenthash to set as recordhash
     */
    function setRecordhash(bytes32 _node, bytes calldata _recordhash) external {
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        require(msg.sender == _owner || isApprovedSigner[_owner][_node][msg.sender], "NOT_AUTHORIZED");
        recordhash[_node] = _recordhash;
        emit RecordhashChanged(msg.sender, _node, _recordhash);
    }

    /**
     * @dev Sets masterhash for a wallet
     * Note - Sets a common masterhash for all names owns by a wallet
     * Note - Only works with off-chain approved signer
     * @param _encodedMasterhash - Masterhash to set as recordhash
     */
    function setMasterhash(bytes calldata _encodedMasterhash) external {
        masterhash[msg.sender] = _encodedMasterhash;
        emit MasterhashChanged(msg.sender, _encodedMasterhash);
    }

    /**
     * @dev Sets recordhash for a level 1 sub.domain.eth of a node
     * Note - Only ENS owner or manager can call
     * @param _subdomain - Level 1 Subdomain label
     * @param _node - Namehash of ENS domain
     * @param _recordhash - Contenthash to set as recordhash
     */
    function setSubRecordhash(string calldata _subdomain, bytes32 _node, bytes calldata _recordhash) external {
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        if (msg.sender == _owner || isApprovedSigner[_owner][_node][msg.sender]) {
            bytes32 _namehash = keccak256(abi.encodePacked(_node, keccak256(bytes(_subdomain))));
            recordhash[_namehash] = _recordhash;
            emit RecordhashChanged(msg.sender, _namehash, _recordhash);
        } else {
            revert NotAuthorized(_node, msg.sender);
        }
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
            bytes1 _identifier = bytes1(0x00); // Set default priority flag to recordhash
            while (index > 0) {
                _namehash = keccak256(abi.encodePacked(_namehash, keccak256(_labels[--index])));
                address __owner = ENS.owner(_namehash);
                // @TODO Redundant if-else [?][!]
                if (ENS.recordExists(_namehash)) {
                    // If ENS record exists on-chain
                    _node = _namehash;
                    (_recordhash, _identifier) = breakParity(_node, __owner);
                } else if (bytes(recordhash[_namehash]).length > 0 || bytes(masterhash[__owner]).length > 0) {
                    // If ENS record does not exist, e.g. off-chain (sub)domain [?]
                    (_recordhash, _identifier) = breakParity(_namehash, __owner);
                }
            }
            if (_recordhash.length == 0) {
                revert("RECORD_NOT_SET");
            }
            string memory _recType = gateway.funcToJson(request); // Filename for the requested record
            address _owner = ENS.owner(_node);
            // Update ownership if domain is wrapped
            if (isWrapper[_owner]) {
                _owner = iToken(_owner).ownerOf(uint256(_node));
            }
            // Update path & domain if masterhash is used
            if (_identifier == bytes1(0x01)) {
                _path = string.concat("eth:", gateway.addressToString(_owner));
                _domain = _path;
            }
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
                "\nOrigin: ",
                _domain,
                "\nApproved Signer: eip155:1:",
                gateway.toChecksumAddress(_approvedSigner),
                "\nOwner: eip155:1:",
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
            require(_signer == iCCIP2ETH(this).getSigner(signRequest, _recordSignature), "BAD_SIGNED_RECORD");
        } else {
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
        emit Approved(msg.sender, _node, _signer, _approval);
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
            emit Approved(msg.sender, _node[i], _signer[i], _approval[i]);
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
        emit UpdateSupportedInterface(_sig, _set);
    }

    /**
     * @dev Add or remove wrapper
     * @param _addr - Address of wrapper
     * @param _set - State to set for wrapper
     */
    function updateWrapper(address _addr, bool _set) external {
        require(msg.sender == gateway.owner(), "ONLY_DEV");
        require(!_set || _addr.code.length > 0, "ONLY_CONTRACT");
        isWrapper[_addr] = _set;
        emit UpdateWrapper(_addr, _set);
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
