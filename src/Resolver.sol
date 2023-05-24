//SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

/**
 * @title : ENS Off-chain Records Manager
 * @author : freetib.eth, sshmatrix.eth
 * https://github.com/namesys-eth/ccip2-eth-resolver
 */

/// @dev : Interfaces
interface iERC165 {
    function supportsInterface(bytes4 interfaceID) external view returns (bool);
}

interface iENS {
    function owner(bytes32 node) external view returns (address);
    function resolver(bytes32 node) external view returns (address);
    function ttl(bytes32 node) external view returns (uint64);
    function recordExists(bytes32 node) external view returns (bool);
    function isApprovedForAll(address owner, address operator) external view returns (bool);
}

interface legacyENS is iENS {
    function setResolver(bytes32 node, address resolver) external;
    function setOwner(bytes32 node, address owner) external;
}

interface iCCIP {
    function resolve(bytes memory name, bytes memory data) external view returns (bytes memory);
    function __callback(bytes calldata response, bytes calldata extraData)
        external
        view
        returns (bytes memory result);
    function signedBy(bytes32 digest, bytes calldata signature) external pure returns (address _addr);
}

interface iIPNS {
    function setContenthash(bytes32 node, bytes calldata _contenthash) external view returns (bytes memory);
}

interface iResolver {
    function contenthash(bytes32 node) external view returns (bytes memory);
    function addr(bytes32 node) external view returns (address payable);
    function pubkey(bytes32 node) external view returns (bytes32 x, bytes32 y);
    function text(bytes32 node, string calldata key) external view returns (string memory value);
    function name(bytes32 node) external view returns (string memory);
    function ABI(bytes32 node, uint256 contentTypes) external view returns (uint256, bytes memory);
    function interfaceImplementer(bytes32 node, bytes4 interfaceID) external view returns (address);
    function zonehash(bytes32 node) external view returns (bytes memory);
    function dnsRecord(bytes32 node, bytes32 name, uint16 resource) external view returns (bytes memory);
    //function recordVersions(bytes32 node) external view returns (uint64);
    /// @dev : set contenthash
    function setContenthash(bytes32 node, bytes calldata hash) external;
}

interface iOverloadResolver {
    function addr(bytes32 node, uint256 coinType) external view returns (bytes memory);
}

interface iToken {
    function ownerOf(uint256 id) external view returns (address);
    function transferFrom(address from, address to, uint256 balance) external;
    function safeTransferFrom(address from, address to, uint256 balance) external;
    function isApprovedForAll(address _owner, address _operator) external view returns (bool);
    function setApprovalForAll(address _operator, bool _approved) external;

    event Approval(address indexed _owner, address indexed _approved, uint256 indexed _tokenId);
    event ApprovalForAll(address indexed _owner, address indexed _operator, bool _approved);
}

interface iERC173 {
    function owner() external view returns (address);
    function transferOwnership(address _newOwner) external;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
}

/// @dev : Gateway Contract
abstract contract Gateway is iERC173 {
    /// Errors & Events
    error ContenthashNotImplemented(bytes1 _type);

    event AddGateway(string indexed domain);
    event RemoveGateway(string indexed domain);

    address immutable THIS = address(this);

    /// @dev : contract owner/multisig address
    address public owner;

    /// @dev : list of gateway domain
    string[] public Gateways;

    /**
     * @dev Selects and constructs random gateways for CCIP-Read Off-chain Lookup
     * @param _path : full path to the record file <record>.json
     * @param k : pseudo-random seeding
     * @return gateways : pseudo-random list of path URLs; URL e.g. https://gateway.tld/ipns/f<ipns-pubkey-hex>/.well-known/eth/<domain>/<record>.json?t=0x0123456789
     */
    function randomGateways(string memory _path, uint256 k) public view returns (string[] memory gateways) {
        uint256 gLen = Gateways.length;
        uint256 len = (gLen / 2) + 1;
        if (len > 5) len = 5;
        gateways = new string[](len);
        for (uint256 i; i < len; i++) {
            k = uint256(keccak256(abi.encodePacked(k, msg.sender)));
            gateways[i] = string.concat("https://", Gateways[k % gLen], _path);
        }
    }

    /**
     * @dev Takes a bytes array and a starting index as input and converts a portion of the bytes array into a hexadecimal string representation
     * @param value : value to format/convert
     */
    function bytesToString(bytes memory _buffer, uint256 _start) public pure returns (string memory) {
        uint256 len = _buffer.length - _start;
        bytes memory result = new bytes((len) * 2);
        bytes memory b16 = bytes("0123456789abcdef");
        uint8 _b;
        for (uint256 i = 0; i < len; i++) {
            _b = uint8(_buffer[i + _start]);
            result[i * 2] = b16[_b / 16];
            result[i * 2 + 1] = b16[_b % 16];
        }
        return string(result);
    }

    /// @dev : Gateway Management Functions

    /// @dev : Modifer to allow admin actions
    modifier onlyDev() {
        require(msg.sender == owner, "NOT_AUTHORISED");
        _;
    }
    
    /**
     * @dev Lists all gateways in an array
     */
    function listAllGateways() external view returns (string[] memory list) {
        return Gateways;
    }

    /**
     * @dev Add single gateway
     * @param _domain : new gateway domain
     */
    function addGateway(string calldata _domain) external onlyDev {
        Gateways.push(_domain);
        emit AddGateway(_domain);
    }

    /**
     * @dev add multiple gateways
     * @param _domains : list of gateway domains to add
     */
    function addGateways(string[] calldata _domains) external onlyDev {
        uint256 len = _domains.length;
        for (uint256 i = 0; i < len; i++) {
            Gateways.push(_domains[i]);
            emit AddGateway(_domains[i]);
        }
    }

    /**
     * @dev Remove single gateway
     * @param _index : gateway index to remove
     */
    function removeGateway(uint256 _index) external onlyDev {
        require(Gateways.length > 1, "LAST_GATEWAY");
        emit RemoveGateway(Gateways[_index]);
        Gateways[_index] = Gateways[Gateways.length - 1];
        Gateways.pop();
    }

    /**
     * @dev Remove gateways from the list
     * @param _indexes : gateway index to remove
     */
    function removeGateways(uint256[] memory _indexes) external onlyDev {
        uint256 len = _indexes.length;
        require(Gateways.length > len, "LAST_GATEWAY");
        for (uint256 i = 0; i < len; i++) {
            emit RemoveGateway(Gateways[_indexes[i]]);
            Gateways[_indexes[i]] = Gateways[Gateways.length - 1];
            Gateways.pop();
        }
    }

    /**
     * @dev Replace single gateway
     * @param _index : gateway index to replace
     * @param _domain : new gateway domain.tld
     */
    function replaceGateway(uint256 _index, string calldata _domain) external onlyDev {
        emit RemoveGateway(Gateways[_index]);
        Gateways[_index] = _domain;
        emit AddGateway(_domain);
    }

    /**
     * @dev Replace multiple gateways
     * @param _indexes : gateway index to replace
     * @param _domains : new gateway domain.tld
     */
    function replaceGateways(uint256[] calldata _indexes, string[] calldata _domains) external onlyDev {
        uint256 len = _indexes.length;
        require(len == _domains.length, "BAD_DOMAINS_LENGTH");
        for (uint256 i = 0; i < len; i++) {
            emit RemoveGateway(Gateways[_indexes[i]]);
            Gateways[_indexes[i]] = _domains[i];
            emit AddGateway(_domains[i]);
        }
    }

    /**
     * @dev Transfer ownership of current contract
     * @param _newOwner : address of new owner
     */
    function transferOwnership(address _newOwner) external onlyDev {
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }

    /**
     * @dev withdraw Ether to owner
     */
    function withdraw() external {
        payable(owner).transfer(THIS.balance);
    }

    /**
     * @dev to be used in case some fungible tokens get locked in the contract
     * @param _token : token address
     * @param _balance : amount to release
     */
    function withdraw(address _token, uint256 _balance) external {
        iToken(_token).transferFrom(THIS, owner, _balance);
    }

    /**
     * @dev to be used in case some non-fungible tokens get locked in the contract
     * @param _token : token address
     * @param _id : token ID to release
     */
    function safeWithdraw(address _token, uint256 _id) external {
        iToken(_token).safeTransferFrom(THIS, owner, _id);
    }
}

/// @dev : Main Resolver Contract
contract Resolver is iCCIP, Gateway {
    /// Errors & Events
    error InvalidSignature(string _message);
    error NotAuthorized(bytes32 _node, address _addr);
    error ContenthashNotSet(bytes32 _node);
    error ResolverFunctionNotImplemented(bytes4 func);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved); // logged when an 'operator' is added or removed
    event Approved(address owner, bytes32 indexed node, address indexed delegate, bool indexed approved); // logged when a 'delegate' is approved or an approval is revoked
    /// @dev ENSIP10 : CCIP-read Off-chain Lookup method (https://eips.ethereum.org/EIPS/eip-3668)
    error OffchainLookup(
        address _addr, // callback contract)
        string[] _gateways, // CCIP gateway URLs
        bytes _data, // {data} field; request value for HTTP call
        bytes4 _callbackFunction, // callback function
        bytes _extradata // callback extra data
    );

    /// @notice : ONLY TESTNET
    /// TODO : Remove before mainnet deployment
    function immolate() external {
        require(msg.sender == owner, "NOT_OWNER");
        selfdestruct(payable(owner));
    }

    /// @dev Resolver function bytes4 selector → Off-chain record filename <record>.json
    mapping(bytes4 => string) public funcToFile;
    /// @dev : Global contenthash; use IPNS for gasless dynamic record updates, or IPFS for static hosting
    mapping(bytes32 => bytes) public contenthash;
    /// @dev : 'One Manager To Rule Them All', since there are multiple approvals in ENS Registries
    mapping(bytes32 => bool) public manager;
    mapping(address => bool) public isWrapper;

    /// @dev : ENS Legacy Registry
    iENS public immutable ENS = iENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);

    /// @dev : ENS Namewrapper
    //iToken public WRAPPER = iToken(0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401);

    /// @dev constructor initial setup
    constructor() {
        funcToFile[iResolver.addr.selector] = "_address/60";
        funcToFile[iResolver.pubkey.selector] = "pubkey";
        funcToFile[iResolver.name.selector] = "name";
        funcToFile[iResolver.contenthash.selector] = "contenthash";
        funcToFile[iResolver.zonehash.selector] = "_dns/zonehash";

        owner = payable(msg.sender);

        Gateways.push("dweb.link");
        emit AddGateway("dweb.link");
        Gateways.push("ipfs.io");
        emit AddGateway("ipfs.io");

        isWrapper[0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401] = true; // mainnet
        emit UpdateWrapper(0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401, true);

        isWrapper[0x114D4603199df73e7D157787f8778E21fCd13066] = true; // goerli
        emit UpdateWrapper(0x114D4603199df73e7D157787f8778E21fCd13066, true);
    }

    /**
     * @dev Approve an operator to update records on all nodes
     * @param _owner : 
     * @param _signer : 
     */
    function setApprovalForAll(address _signer, bool _approved) external {
        manager[keccak256(abi.encodePacked("manage-all", msg.sender, _signer))];
        emit ApprovalForAll(msg.sender, _signer, _approved);
    }

    /**
     * @dev Checks if an operator can update records on all nodes
     * @param _owner : 
     * @param _signer : 
     */
    function isApprovedForAll(address _owner, address _signer) public view returns (bool) {
        return manager[keccak256(abi.encodePacked("manage-all", _owner, _signer))];
    }

    /**
     * @dev Approve a Delegate to be able to updated records on a node
     */
    function approve(bytes32 _node, address _signer, bool _approved) external {
        manager[keccak256(abi.encodePacked("manage-one", _node, msg.sender, _signer))];
        emit Approved(msg.sender, _node, _signer, _approved);
    }

    /**
     * @dev Check to see if the delegate has been approved by the owner for the node
     */
    function isApprovedFor(address _owner, bytes32 _node, address _signer) public view returns (bool) {
        return manager[keccak256(abi.encodePacked("manage-one", _node, _owner, _signer))];
    }
    /**
     * @dev : Check if _signer is approved to manage _node records
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

    /**
     * @dev get signer from signature & digest
     * @param digest : hash of signed message
     * @param signature : signature to verify
     * @return _addr : address of signer
     * signature is 64 bytes bytes32(R)+bytes32(VS) compact
     * or 65 bytes bytes32(R)+bytes32(S)+bytes1(V) long
     * TODO: signed by contract? or leave it for offchain only?
     */
    function signedBy(bytes32 digest, bytes calldata signature) external pure returns (address _addr) {
        bytes32 r = bytes32(signature[:32]);
        bytes32 s;
        uint8 v;
        if (signature.length == 64) {
            // compact bytes32 *2
            bytes32 vs = bytes32(signature[32:]);
            s = vs & bytes32(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
            v = uint8((uint256(vs) >> 255) + 27);
        } else if (signature.length == 65) {
            // packed bytes32 * 2 + uint8
            s = bytes32(signature[32:64]);
            v = uint8(bytes1(signature[64:]));
        } else if (signature.length == 96) {
            // longest bytes32 * 3
            s = bytes32(signature[32:64]);
            v = uint8(uint256(bytes32(signature[64:])));
        } else {
            revert InvalidSignature("BAD_SIG_LENGTH");
        }
        if (s > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert InvalidSignature("INVALID_S_VALUE");
        }
        _addr = ecrecover(digest, v, r, s);
        if (_addr == address(0)) {
            revert InvalidSignature("ZERO_ADDRESS");
        }
    }

    /**
     * @dev Interface Selector
     * @param interfaceID : interface identifier
     */
    function supportsInterface(bytes4 interfaceID) external pure returns (bool) {
        return (
            interfaceID == iCCIP.resolve.selector || interfaceID == iResolver.setContenthash.selector
                || interfaceID == type(iERC173).interfaceId || interfaceID == iCCIP.__callback.selector
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

    function setContenthash(bytes32 _node, bytes calldata _contenthash) external isAuthorized(_node) {
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

            bytes4 func = bytes4(data[:4]);
            string memory _jsonPath;
            if (bytes(funcToFile[func]).length > 0) {
                _jsonPath = funcToFile[func];
            } else if (func == iResolver.text.selector) {
                _jsonPath = abi.decode(data[36:], (string));
            } else if (func == iOverloadResolver.addr.selector) {
                _jsonPath = string.concat("_address/", uintToString(abi.decode(data[36:], (uint256))));
            } else if (func == iResolver.interfaceImplementer.selector) {
                _jsonPath =
                    string.concat("_interface/0x", bytesToString(abi.encodePacked(abi.decode(data[36:], (bytes4))), 0));
            } else if (func == iResolver.ABI.selector) {
                _jsonPath = string.concat("_abi/", uintToString(abi.decode(data[36:], (uint256))));
            } else if (func == iResolver.dnsRecord.selector) {
                /// @dev : TODO, use latest ENS codes/ENSIP for DNS records
                (bytes32 _name, uint16 resource) = abi.decode(data[36:], (bytes32, uint16));
                _jsonPath =
                    string.concat("_dns/0x", bytesToString(abi.encodePacked(_name), 0), "/", uintToString(resource));
            } else {
                revert ResolverFunctionNotImplemented(func);
            }
            bytes32 _checkHash =
                keccak256(abi.encodePacked(THIS, blockhash(block.number - 1), msg.sender, _domain, _jsonPath));
            revert OffchainLookup(
                THIS,
                randomGateways(
                    string.concat(
                        _ipns[0] == 0xe5 ? "/ipns/f" : "/ipfs/f",
                        bytesToString(_ipns, 2),
                        "/.well-known/",
                        _path,
                        "/",
                        _jsonPath,
                        ".json?t={data}"
                    ),
                    uint256(_checkHash)
                ),
                abi.encodePacked(uint64(block.timestamp / 60) * 60),
                iCCIP.__callback.selector,
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
                && _checkHash == keccak256(abi.encodePacked(THIS, blockhash(_blocknumber), msg.sender, _domain, _jsonPath)),
            "INVALID_CHECKSUM/TIMEOUT"
        );
        if (bytes4(response[:4]) != iCCIP.__callback.selector) {
            revert InvalidSignature("BAD_PREFIX");
        }
        address _signer;
        bytes memory signature;
        (_signer, signature, result) = abi.decode(response[4:], (address, bytes, bytes));
        string memory _req = string.concat(
            "Requesting signature for off-chain ENS record\n",
            //"\////IMPORTANT: Please verify the integrity and authenticity of connected Off-chain ENS Records Manager before signing this message\n",
            "\nENS Domain: ",
            _domain,
            "\nRecord Type: ",
            _jsonPath,
            "\nRecord Hash: 0x",
            bytesToString(abi.encodePacked(keccak256(result)), 0),
            "\nSigned By: eip155:1:",
            toChecksumAddress(_signer)
        );
        bytes32 _digest =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", uintToString(bytes(_req).length), _req));
        if (_signer != iCCIP(THIS).signedBy(_digest, signature)) {
            revert InvalidSignature("BAD_SIGNER");
        }
        address _owner = ENS.owner(_node);
        if (isWrapper[_owner]) {
            _owner = iToken(_owner).ownerOf(uint256(_node));
        }
        if (
            _signer != _owner && !manager[keccak256(abi.encodePacked("manage-one", _node, _owner, _signer))]
                && !manager[keccak256(abi.encodePacked("manage-all", _owner, _signer))]
        ) revert NotAuthorized(_node, _signer);
    }

    /**
     * @dev : uint to number string
     * @param value : uint value
     */
    function uintToString(uint256 value) public pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        unchecked {
            while (temp != 0) {
                ++digits;
                temp /= 10;
            }
            bytes memory buffer = new bytes(digits);
            while (value != 0) {
                buffer[--digits] = bytes1(uint8(48 + (value % 10)));
                value /= 10;
            }
            return string(buffer);
        }
    }

    /// @dev : address to checksum address string
    function toChecksumAddress(address _addr) public pure returns (string memory) {
        bytes memory _buffer = abi.encodePacked(_addr);
        bytes memory result = new bytes(40); //bytes20*2
        bytes memory B16 = "0123456789ABCDEF";
        bytes memory b16 = "0123456789abcdef";
        bytes32 hash = keccak256(abi.encodePacked(bytesToString(_buffer, 0)));
        uint256 high;
        uint256 low;
        for (uint256 i; i < 20; i++) {
            high = uint8(_buffer[i]) / 16;
            low = uint8(_buffer[i]) % 16;
            result[i * 2] = uint8(hash[i]) / 16 > 7 ? B16[high] : b16[high];
            result[i * 2 + 1] = uint8(hash[i]) % 16 > 7 ? B16[low] : b16[low];
        }
        return string.concat("0x", string(result));
    }

    /// @dev : Resolver Management functions

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

    event UpdateFuncFile(bytes4 _func, string _name);

    function addFuncMap(bytes4 _func, string calldata _name) external onlyDev {
        funcToFile[_func] = _name;
        emit UpdateFuncFile(_func, _name);
    }
}
