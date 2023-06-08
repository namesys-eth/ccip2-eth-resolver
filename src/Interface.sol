// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

interface iERC165 {
    function supportsInterface(bytes4 interfaceID) external view returns (bool);
}

interface iERC173 {
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function owner() external view returns (address);
    function transferOwnership(address _newOwner) external;
}

interface iENS {
    function owner(bytes32 node) external view returns (address);
    function resolver(bytes32 node) external view returns (address);
    function ttl(bytes32 node) external view returns (uint64);
    function recordExists(bytes32 node) external view returns (bool);
    function isApprovedForAll(address owner, address operator) external view returns (bool);
}

interface iENSIP10 {
    function resolve(bytes memory _name, bytes memory _data) external view returns (bytes memory);

    error OffchainLookup(address _to, string[] _gateways, bytes _data, bytes4 _callbackFunction, bytes _extradata);
}

interface iCCIP2ETH is iENSIP10 {
    function __callback(bytes calldata _response, bytes calldata _extraData)
        external
        view
        returns (bytes memory _result);

    function signedBy(string calldata _signRequest, bytes calldata _signature)
        external
        view
        returns (address _signer);
    function setRecordhash(bytes32 _node, bytes calldata _contenthash) external;
    function recordhash(bytes32 _node) external view returns (bytes memory _contenthash);
}

interface iGatewayManager is iERC173 {
    function randomGateways(bytes calldata _recordhash, string memory _path, uint256 k)
        external
        view
        returns (string[] memory gateways);
    function uintToString(uint256 value) external pure returns (string memory);
    function bytesToHexString(bytes calldata _buffer, uint256 _start) external pure returns (string memory);
    function funcToJson(bytes calldata data) external view returns (string memory _jsonPath);
    function listGateways() external view returns (string[] memory list);
    function toChecksumAddress(address _addr) external pure returns (string memory);
    //
    function __fallback(bytes4 _type) external view returns (address signer, bytes memory result);
    function chunk(bytes calldata _b, uint256 _start, uint256 _end) external pure returns (bytes memory);
    /// write functions
    function addFuncMap(bytes4 _func, string calldata _name) external;
    function addGateway(string calldata _domain) external;
    // function addGateways(string[] calldata _domains) external;
    function removeGateway(uint256 _index) external;
    //function removeGateways(uint256[] memory _indexes) external;
    function replaceGateway(uint256 _index, string calldata _domain) external;
    //function replaceGateways(uint256[] calldata _indexes, string[] calldata _domains) external;
}

interface iUtils {}

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
    function recordVersions(bytes32 node) external view returns (uint64);
    function approved(bytes32 _node, address _signer) external view returns (bool);
}

interface iOverloadResolver {
    function addr(bytes32 node, uint256 coinType) external view returns (bytes memory);
    function dnsRecord(bytes32 node, bytes memory name, uint16 resource) external view returns (bytes memory);
}

interface iToken {
    function ownerOf(uint256 id) external view returns (address);
    function transferFrom(address from, address to, uint256 bal) external;
    function safeTransferFrom(address from, address to, uint256 bal) external;
    //function isApprovedForAll(address _owner, address _operator) external view returns (bool);
    //function setApprovalForAll(address _operator, bool _approved) external;
    //event Approval(address indexed _owner, address indexed _approved, uint256 indexed _tokenId);
    //event ApprovalForAll(address indexed _owner, address indexed _operator, bool _approved);
}
// owner = owner of domain.eth
// manager = on chain approved by owner
// signer = record's result signer

interface iCallbackType {
    /// @dev : signer = signer of result
    /// signer is owner or manager or offchain approved key
    /// approved signature is checked if signer is not owner or manager
    /// approval must be signed by owner or manager
    /// if signer is owner/manager?
    /// >> approved Signature = not used, fill-in length >1 ~ <32 bytes with anything
    function signedRecord(
        address signer,
        bytes memory recordSignature,
        bytes memory approvedSignature,
        bytes memory result
    ) external view returns (bytes memory);

    //=================

    // inputs use *almost* same rule as above "signedRecord(..)" function
    // tldr; sorry mario, your princess is in another castle
    // experimental: recursive ccip-read/offchain lookup
    // +1 revert "OffchainLookup(...)" for second "callback2(..)"
    // if approved signature length == 1, signer is owner/manager
    // if approved signature length >1, signed by owner/manager to approve signer
    // signer is one who signed redirecthash = signautre
    // same signer have to sign recursive records under redirected recordhash
    // redirecthash is ipfs/ipns/... contenthash
    function signedRedirect(address _signer, bytes memory _signature, bytes memory _extradata, bytes memory _redirect)
        external
        view
        returns (bytes memory);

    ///================

    function signedDappService(
        address signer,
        bytes memory signature,
        bytes memory approvedSignature,
        bytes memory name // encoded name of domain
    ) external view returns (bytes memory);
    // ^^ extended redirect feature
    // dapphash is namehash of ..*.eth to redirect (on/off-chain read & return records)
    // eg: ens.domain.eth >> app.ens.eth, dapp
    // eg: high-priest.domain.eth >> vitalik.eth, why not
    // eg: bensyc.domain.eth >> 421.bensyc.eth, nft/profile
    // eg: swap.domain.eth >> app.uniswap.eth, defi
    // experimental: DApp store/NIP02 type flat petname as sub.domain.eth
    // Users can "install" *.eth in their ENS as *.domain.eth, offchain
    // + meta list of all installed dapps in dapp.domain.eth
    // + Namesys dappstore with a public list of "installable" *.eth dapps

    //?? allow gateway filter specific resolver function where plaintext "NOT signed" records are ok?
    // eg meta records/ indexer .json types as text/subdomain level?
    //function notSignedRecord(bytes memory result) external view returns(bytes memory);
}
