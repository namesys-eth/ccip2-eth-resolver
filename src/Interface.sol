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

    function getSigner(string calldata _signRequest, bytes calldata _signature)
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
    function __fallback(bytes calldata response, bytes calldata extradata)
        external
        view
        returns (bytes memory result);
    function chunk(bytes calldata _b, uint256 _start, uint256 _end) external pure returns (bytes memory);
    function addFuncMap(bytes4 _func, string calldata _name) external;
    function addGateway(string calldata _domain) external;
    function removeGateway(uint256 _index) external;
    function replaceGateway(uint256 _index, string calldata _domain) external;
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
}

// Note - Owner = Owner of domain.eth
// Note - Manager = On-/Off-chain address approved by Owner
// Note - Signer = Record signer
interface iCallbackType {
    function signedRecord(
        address recordSigner, // Owner OR On-chain Manager OR Off-chain Manager
        bytes memory recordSignature, // Signature from signer for result value
        bytes memory approvedSignature, // bytes1(..) IF signer is owner or on-chain manager
        bytes memory result // ABI-encoded result
    ) external view returns (bytes memory);
}
