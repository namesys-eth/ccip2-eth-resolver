// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

/// @title :
/// @author : 0xc0de4c0ffee.eth, sshmatrix.eth

interface iCCIP {
    function resolve(bytes memory name, bytes memory data) external view returns (bytes memory);
}

interface iOverloadResolver {
    function addr(bytes32 node, uint256 coinType) external view returns (bytes memory);
}

interface iResolver {
    function contenthash(bytes32 node) external view returns (bytes memory);

    function addr(bytes32 node) external view returns (address payable);

    function pubkey(bytes32 node) external view returns (bytes32 x, bytes32 y);

    function text(bytes32 node, string calldata key) external view returns (string memory);

    function name(bytes32 node) external view returns (string memory);

    function ABI(bytes32 node, uint256 contentTypes) external view returns (uint256, bytes memory);

    function interfaceImplementer(bytes32 node, bytes4 interfaceID) external view returns (address);

    function zonehash(bytes32 node) external view returns (bytes memory);

    function dnsRecord(bytes32 node, bytes32 name, uint16 resource) external view returns (bytes memory);

    //function recordVersions(bytes32 node) external view returns (uint64);
}

interface iENS {
    function owner(bytes32 node) external view returns (address);

    function resolver(bytes32 node) external view returns (address);

    function ttl(bytes32 node) external view returns (uint64);

    function recordExists(bytes32 node) external view returns (bool);

    function isApprovedForAll(address _owner, address operator) external view returns (bool);
}

interface iERC165 {
    function supportsInterface(bytes4 interfaceID) external view returns (bool);
}

interface iToken {
    function transferFrom(address from, address to, uint256 bal) external;
    function safeTransferFrom(address from, address to, uint256 bal) external;
}

contract xCCIP2ETH is iCCIP {
    address private immutable THIS = address(this);

    /// @dev : owner/multisig address
    address payable public owner;

    iENS public ENS; // ENS contract

    /// @dev : root .eth namehash
    bytes32 public immutable ethNamehash = keccak256(abi.encodePacked(bytes32(0), keccak256("eth")));

    // @dev default for *.CCIP2.eth
    // 0 "bafzaajaiaejcapc2xjwjwucvux5beka4jbqyr3mk4k3o6oklhwmbwagrpjfvc424"
    string public DefaultIPNS = "k51qzi5uqu5dhoqqxyty5eefk5pjwgmh4eeci1s09k1egnzajwg3mh3fynsti4";
    //hex'e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c';

    // @dev home content for CCIP2.eth
    // 1 "bafzaajaiaejcay3x7z7ftabmy4larbxphcgs5wt2djx32savmfjzoxsehlunabby"
    // bytes public HomeContenthash = hex'e50101720024080112206377fe7e59802cc7160886ef388d2eda7a1a6fbd48156153975e443ae8d00438';

    /// @dev : CCIP lookup https://eips.ethereum.org/EIPS/eip-3668
    error OffchainLookup(
        address _src, // this callback contract
        string[] _gateways, // CCIP gateway urls
        bytes _data, // {data} value for request
        bytes4 _callbackFunction, // callback function
        bytes _extraData // callback extradata
    );

    mapping(bytes4 => string) public funcMap; // bytes4 function selector >> string <name>.json

    constructor() {
        funcMap[iResolver.addr.selector] = "addr-60"; // eth address
        funcMap[iResolver.pubkey.selector] = "pubkey";
        funcMap[iResolver.name.selector] = "name";
        funcMap[iResolver.zonehash.selector] = "zonehash";
        owner = payable(msg.sender);
    }

    /// @dev : namehash of CCIP2.eth

    bytes32 public immutable DomainNamehash =
        keccak256(abi.encodePacked(keccak256(abi.encodePacked(bytes32(0), keccak256("eth"))), keccak256("ccip2")));

    function selfD() external {
        // testnet
        require(msg.sender == owner, "Only owner");
        selfdestruct(owner);
    }

    function supportsInterface(bytes4 interfaceID) external pure returns (bool) {
        return (interfaceID == iCCIP.resolve.selector || interfaceID == iERC165.supportsInterface.selector);
    }

    function resolveContenthash(bytes memory label) public view returns (bytes memory) {}

    // contenthash callback
    function ___contenthash(bytes calldata response, bytes calldata extraData)
        external
        view
        returns (bytes memory result)
    {
        bytes memory signature;
        if (bytes4(response[:4]) == xCCIP2ETH.___contenthash.selector) {
            (result, signature) = abi.decode(response[4:], (bytes, bytes));
            // TODO : verify signature
        } else {
            result = response;
        }
        // timeout check
        (uint256 _bn, bytes32 _check) = abi.decode(extraData, (uint256, bytes32));
        require(
            block.number <= _bn + 1 // timeout in 1 blocks
                && _check == keccak256(abi.encodePacked(blockhash(--_bn), THIS, msg.sender, result)),
            "Invalid Checksum"
        );
        // ethers js/ccip reverts if this result is not abi encoded
    }

    mapping(bytes32 => string) public ipnsHash; // IPNS for gasless dynamic record updates
    //mapping(bytes32 => bytes) public signedcontent; // contenthash signed by owner/approved in ENS
    mapping(bytes32 => bool) public manager; // manager/signer

    function setIPNS(bytes32 node, string calldata _ipns) public {
        //require(bytes1(_ipns[:1])) == bytes1('k'), "Only IPNS");
        address _owner = ENS.owner(node);
        // check namewrapper?
        require(
            msg.sender == _owner || manager[keccak256(abi.encodePacked(node, _owner, msg.sender))], "Only Owner/Manager"
        );
        ipnsHash[node] = _ipns;
    }

    function approve(bytes32 node, bool _approved) external {
        address _owner = ENS.owner(node);
        require(msg.sender == owner, "Only Owner/Manager");
        manager[keccak256(abi.encodePacked(node, _owner, msg.sender))] = _approved;
    }
    /// @dev : Gateway struct

    struct Gate {
        string domain; // "domain.tld" ipfs gateway
        uint8 _type; // 0 for hash.ipns.gateway.tld, >0 for gateway.tld/ipns/hash
    }

    Gate[] public Gateways;
    /**
     * @dev Selects and construct random gateways for CCIP resolution
     * @param _ipns : name to resolve on testnet e.g. alice.eth
     * @return urls : ordered list of gateway URLs for HTTP calls
     */

    function randomGateways(string memory _ipns, string memory _path) public view returns (string[] memory urls) {
        uint256 gLen = Gateways.length;
        uint256 len = (gLen / 2) + 1;
        if (len > 5) len = 5;
        urls = new string[](len);
        // pseudo random seeding
        uint256 k = uint256(keccak256(abi.encodePacked(_ipns, msg.sender, blockhash(block.number - 1))));
        for (uint256 i; i < len;) {
            k = uint256(keccak256(abi.encodePacked(k, msg.sender))) % gLen;
            // Gateway @ URL e.g. https://example.xyz/eip155:1/alice.eth/{data}
            urls[i++] = Gateways[k]._type == 0
                ? string.concat("https://", _ipns, ".", Gateways[k].domain, "/", _path)
                : string.concat("https://", Gateways[k].domain, "/ipns/", _ipns, "/", _path);
            //string.concat("https://", Gateways[k]._domain, "/eip155", ":", chainID, "/", _ipns, "/{data}");
        }
    }

    function resolve(bytes calldata name, bytes calldata data) external view returns (bytes memory) {
        unchecked {
            uint256 index; // domain level index
            uint256 i = 1; // counter
            uint256 len = uint8(bytes1(name[:1])); // length of label
            bytes[] memory _labels = new bytes[](42); // max 42 level sub.sub...domain.eth
            _labels[index++] = name[1:i += len];

            string memory _path = string(_labels[0]); // suffix after /.well-known/..
            string memory _domain = _path; // full domain as string

            while (name[i] > 0x0) {
                // dns decode
                len = uint8(bytes1(name[i:++i]));
                _labels[index] = name[i:i += len];
                _domain = string.concat(_domain, ".", string(_labels[index]));
                _path = string.concat(string(_labels[index]), "/", _path);
                ++index;
            }

            bool dotETH = (keccak256(abi.encodePacked(bytes32(0), keccak256(_labels[index - 1]))) == ethNamehash);

            bytes4 func = bytes4(data[:4]); // 4 bytes identifier
            //if (func == iResolver.contenthash.selector) {
            // handle contenthash 1st
            bytes32 _nh; // last namehash
            bytes32 _namehash = keccak256(abi.encodePacked(bytes32(0), keccak256(bytes(_labels[--index])))); // last label/tld ?".eth"
            string memory _ipns = DefaultIPNS;
            while (index > 0) {
                _namehash = keccak256(abi.encodePacked(_namehash, keccak256(bytes(_labels[--index]))));
                if (bytes(ipnsHash[_namehash]).length != 0) {
                    _ipns = ipnsHash[_namehash];
                    _nh = _namehash;
                }
            }
            // should never revert with ENSIP10 compatible apps/wallets
            require(_namehash == bytes32(data[4:36]), "Bad Namehash");

            //if (signedcontent[_nh].length > 0) { // check owner's signature
            //    _ipns = bytes.concat(xCCIP2ETH.___contenthash.selector, abi.encode(_ipns, signedcontent[_nh]));
            //}

            string[] memory _urls = new string[](2);
            if (dotETH) {
                _urls[0] = 'data:text/plain,{"data":"{data}"}';
                _urls[1] = 'data:application/json,{"data":"{data}"}';
            } //else {
                // non .eth need ch?
                //_urls[0] = string.concat("https://", _domain, "/.well-known/", _path, "/contenthash.json?t={data}");
                //_urls[1] = string.concat("https://", _domain, "/.well-known/", _path, "/contenthash.json?t={data}"); // retry
                //revert("NOT-ETH");
            //}
            revert OffchainLookup(
                THIS, // callback contract
                _urls, // gateway URL array
                "", //_ipns, // {data} field
                xCCIP2ETH.___contenthash.selector, // callback function
                abi.encode( // extradata
                    block.number, // checkpoint
                    keccak256(abi.encodePacked(THIS, blockhash(block.number - 1), msg.sender, _ipns))
                )
            );
            //}

            string memory _jsonPath;
            if (func == iResolver.text.selector) {
                _jsonPath = abi.decode(data[36:], (string));
            } else if (func == iOverloadResolver.addr.selector) {
                _jsonPath = string.concat("addr-", uintToNumString(abi.decode(data[36:], (uint256))));
            } else {
                _jsonPath = funcMap[func];
                require(bytes(_jsonPath).length != 0, "Resolver Function NOT Implemented");
            }

            string[] memory _gateways = new string[](3);
            // TODO : make gateway lists to updatable array ?randomize weight.
            if (dotETH) {
                _gateways[0] = string.concat("https://", _domain, ".limo/.well-known/", _jsonPath, ".json?t={data}");
                _gateways[1] = string.concat("https://", _domain, ".casa/.well-known/", _jsonPath, ".json?t={data}");
                _gateways[2] = string.concat("https://", _domain, ".link/.well-known/", _jsonPath, ".json?t={data}");
            } else {
                _gateways[0] = string.concat("https://", _domain, "/.well-known/", _jsonPath, ".json?t1={data}");
                _gateways[1] = string.concat("https://", _domain, "/.well-known/", _jsonPath, ".json?t2={data}");
                _gateways[2] = string.concat("https://", _domain, "/.well-known/", _jsonPath, ".json?t3={data}");
            }
            revert OffchainLookup(
                THIS, // callback contract
                _gateways, // gateway URL array
                abi.encodePacked(uint32(block.timestamp / 60) * 60), // {data} = 0xtimestamp, nocache after 60 seconds
                xCCIP2ETH.__callback.selector, // callback function
                abi.encode( // extradata
                    block.number, // checkpoint
                    keccak256(data), // namehash + calldata
                    keccak256(abi.encodePacked(THIS, blockhash(block.number - 1), msg.sender, keccak256(data)))
                )
            );
        }
    }

    // basic callback
    function __callback(bytes calldata response, bytes calldata extraData) external view returns (bytes memory) {
        (uint256 _bn, bytes32 _dh, bytes32 _check) = abi.decode(extraData, (uint256, bytes32, bytes32));
        require(
            block.number <= _bn + 3 // timeout in 3 blocks, + 3 * ~13 seconds, check >ipfs gateway timeout
                && _check == keccak256(abi.encodePacked(blockhash(--_bn), THIS, msg.sender, _dh)),
            "Invalid Checksum"
        );
        // json data must be abi encoded
        return response;
    }

    function uintToNumString(uint256 value) public pure returns (string memory) {
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

    /// @dev : resolver management

    /// @dev : Gateway and Chain Management Functions
    modifier onlyDev() {
        require(msg.sender == owner, "Only Dev");
        _;
    }

    event AddGateway(string indexed domain, uint8 indexed _type, address indexed _dev);
    event RemoveGateway(string indexed domain, uint8 indexed _type, address indexed _dev);
    /**
     * @dev Push new gateway to the list
     * @param domain : new gateway domain
     * @param _type : type of new gateway
     */

    function addGateway(string calldata domain, uint8 _type) external onlyDev {
        Gateways.push(Gate(domain, _type));
        emit AddGateway(domain, _type, msg.sender);
    }

    /**
     * @dev Remove gateway from the list
     * @param _index : gateway index to remove
     */
    function removeGateway(uint256 _index) external onlyDev {
        require(Gateways.length > 1, "Last Gateway");
        Gate memory _g = Gateways[_index];
        unchecked {
            if (Gateways.length > _index + 1) {
                Gateways[_index] = Gateways[Gateways.length - 1];
            }
        }
        Gateways.pop();
        emit RemoveGateway(_g.domain, _g._type, msg.sender);
    }

    /**
     * @dev Replace gateway for a given controller
     * @param _index : gateway index to replace
     * @param _type : type of gateway
     * @param domain : new gateway domain
     */
    function replaceGateway(uint256 _index, string calldata domain, uint8 _type) external onlyDev {
        Gate memory _g = Gateways[_index];
        Gateways[_index] = Gate(domain, _type);
        emit AddGateway(domain, _type, msg.sender);
        emit RemoveGateway(_g.domain, _g._type, msg.sender);
    }

    /// @dev : revert on fallback
    fallback() external payable {
        revert();
    }

    /// @dev : ?revert on receive
    receive() external payable {
        //revert();
    }

    /**
     * @dev : withdraw ether to owner
     */
    function withdraw() external {
        owner.transfer(THIS.balance);
    }

    /**
     * @dev : to be used in case some tokens get locked in the contract
     * @param _token : token to release
     * @param _bal : amount to release
     */
    function withdraw(address _token, uint256 _bal) external {
        iToken(_token).transferFrom(THIS, owner, _bal);
    }

    /**
     * @dev : to be used in case some tokens get locked in the contract
     * @param _token : token to release
     * @param _id : id to release
     */
    function safeWithdraw(address _token, uint256 _id) external {
        iToken(_token).safeTransferFrom(THIS, owner, _id);
    }
}
