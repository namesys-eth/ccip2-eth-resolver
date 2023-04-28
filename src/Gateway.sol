// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

import "./Interface.sol";

abstract contract Gateway is iERC173 {
    address immutable THIS = address(this);

    /// @dev : contract owner/multisig address
    address public owner;

    /// @dev : list of gateway domain
    string[] public Gateways;

    /**
     * @dev Selects and construct random gateways for CCIP resolution
     * @param _path : full path for records.json
     * @param k : pseudo random seeding
     * @return gateways : pseudo random list of gateway URLs for CCIP-Read
     * Gateway URL e.g. https://gateway.tld/ipns/f<ipns-hash-hex>/.well-known/eth/virgil/<records>.json?t1=0x0123456789
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

    error ContenthashNotImplemented(bytes1 _type);

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

    modifier onlyDev() {
        require(msg.sender == owner, "Only Dev");
        _;
    }

    event AddGateway(string indexed domain);
    event RemoveGateway(string indexed domain);

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
        require(Gateways.length > 1, "Last Gateway");
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
        require(Gateways.length > len, "Last Gateway");
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
        require(len == _domains.length, "Bad input lengths");
        for (uint256 i = 0; i < len; i++) {
            emit RemoveGateway(Gateways[_indexes[i]]);
            Gateways[_indexes[i]] = _domains[i];
            emit AddGateway(_domains[i]);
        }
    }
    /**
     * Transfer ownership of resolver contract
     * @param _newOwner : address of new multisig
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
