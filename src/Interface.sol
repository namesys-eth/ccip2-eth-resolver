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
    error OffchainLookup(address _to, string[] _gateways, bytes _data, bytes4 _callbackFunction, bytes _extradata);

    function resolve(bytes memory _name, bytes memory _data) external view returns (bytes memory);
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
    function setRecordhash(bytes32 _node, bytes calldata _recordhash) external payable;
    function setShortRecordhash(bytes32 _node, bytes32 _recordhash) external payable;
    function setSubRecordhash(bytes32 _node, string memory _subdomain, bytes calldata _recordhash) external payable;
    function setDeepSubRecordhash(bytes32 _node, string[] memory _subdomains, bytes calldata _recordhash)
        external
        payable;
    function setOwnerhash(bytes calldata _recordhash) external payable;
    function redirectService(bytes calldata _encoded, bytes calldata _requested)
        external
        view
        returns (bytes4 _selector, bytes32 _namehash, bytes memory _redirectRequest, string memory _domain);
}

interface iGatewayManager is iERC173 {
    function randomGateways(bytes calldata _recordhash, string memory _path, uint256 k)
        external
        view
        returns (string[] memory gateways);
    function uintToString(uint256 value) external pure returns (string memory);
    function bytesToHexString(bytes calldata _buffer, uint256 _start) external pure returns (string memory);
    function bytes32ToHexString(bytes32 _buffer) external pure returns (string memory);
    function funcToJson(bytes calldata _request) external view returns (string memory _jsonPath);
    function toChecksumAddress(address _addr) external pure returns (string memory);
    function __fallback(bytes calldata response, bytes calldata extradata)
        external
        view
        returns (bytes memory result);
    function addFuncMap(bytes4 _func, string calldata _name) external;
    function listWeb2Gateways() external view returns (string[] memory list);
    function addWeb2Gateway(string calldata _domain) external;
    function removeWeb2Gateway(uint256 _index) external;
    function replaceWeb2Gateway(uint256 _index, string calldata _domain) external;
    function listWeb3Gateways() external view returns (string[] memory list);
    function addWeb3Gateway(string calldata _domain) external;
    function removeWeb3Gateway(uint256 _index) external;
    function replaceWeb3Gateway(uint256 _index, string calldata _domain) external;
    function formatSubdomain(bytes calldata _recordhash) external pure returns (string memory result);
    function isWeb2(bytes calldata _recordhash) external pure returns (bool);
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
// Note - Manager = On-/Off-Chain address approved by Owner
// Note - Signer = Record signer
interface iCallbackType {
    function signedRecord(
        address recordSigner, // Owner OR On-Chain Manager OR Off-Chain Manager
        bytes memory recordSignature, // Signature from signer for result value
        bytes memory approvedSignature, // bytes length >0 & <64 IF signer is owner or on-chain approved manager
        bytes memory result // ABI-encoded result
    ) external view returns (bytes memory);

    function signedRedirect(
        address recordSigner, // Owner OR On-Chain Manager OR Off-Chain Manager
        bytes memory recordSignature, // Signature from signer for redirect value
        bytes memory approvedSignature, // bytes length >0 & <64 IF signer is owner or on-chain approved manager
        bytes memory redirect // DNS-encoded sub/domain.eth to redirect
    ) external view returns (bytes memory);
}
