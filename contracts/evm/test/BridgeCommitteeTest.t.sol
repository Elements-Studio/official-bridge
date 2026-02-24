// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BridgeBaseTest.t.sol";
import "../contracts/utils/BridgeUtils.sol";

contract BridgeCommitteeTest is BridgeBaseTest {
    // This function is called before each unit test
    function setUp() public {
        setUpBridgeTest();
    }

    function testBridgeCommitteeInitialization() public {
        assertEq(committee.committeeStake(committeeMemberA), 1000);
        assertEq(committee.committeeStake(committeeMemberB), 1000);
        assertEq(committee.committeeStake(committeeMemberC), 1000);
        assertEq(committee.committeeStake(committeeMemberD), 2002);
        assertEq(committee.committeeStake(committeeMemberE), 4998);
        // Assert that the total stake is 10,000
        assertEq(
            committee.committeeStake(committeeMemberA) + committee.committeeStake(committeeMemberB)
                + committee.committeeStake(committeeMemberC)
                + committee.committeeStake(committeeMemberD)
                + committee.committeeStake(committeeMemberE),
            10000
        );
        // Check that the blocklist and nonces are initialized to zero
        assertEq(committee.blocklist(address(committeeMemberA)), false);
        assertEq(committee.blocklist(address(committeeMemberB)), false);
        assertEq(committee.blocklist(address(committeeMemberC)), false);
        assertEq(committee.blocklist(address(committeeMemberD)), false);
        assertEq(committee.blocklist(address(committeeMemberE)), false);
        assertEq(committee.nonces(0), 0);
        assertEq(committee.nonces(1), 0);
        assertEq(committee.nonces(2), 0);
        assertEq(committee.nonces(3), 0);
        assertEq(committee.nonces(4), 0);
    }

    function testBridgeCommitteeInitializationLength() public {
        address[] memory _committeeMembers = new address[](256);

        for (uint160 i = 0; i < 256; i++) {
            _committeeMembers[i] = address(i);
        }

        address _committee = Upgrades.deployUUPSProxy("BridgeCommittee.sol", "", opts);

        vm.expectRevert(bytes("BridgeCommittee: Committee length must be less than 256"));
        BridgeCommittee(_committee).initialize(
            _committeeMembers, new uint16[](256), minStakeRequired
        );
    }

    function testBridgeCommitteeInitializeConfig() public {
        vm.expectRevert(bytes("BridgeCommittee: Config already initialized"));
        // Initialize the committee with the config contract
        committee.initializeConfig(address(101));
    }

    function testBridgeFailInitialization() public {
        // Test fail initialize: Committee Duplicate Committee Member
        address[] memory _committeeDuplicateCommitteeMember = new address[](5);
        _committeeDuplicateCommitteeMember[0] = committeeMemberA;
        _committeeDuplicateCommitteeMember[1] = committeeMemberB;
        _committeeDuplicateCommitteeMember[2] = committeeMemberC;
        _committeeDuplicateCommitteeMember[3] = committeeMemberD;
        _committeeDuplicateCommitteeMember[4] = committeeMemberA;

        uint16[] memory _stakeDuplicateCommitteeMember = new uint16[](5);
        _stakeDuplicateCommitteeMember[0] = 1000;
        _stakeDuplicateCommitteeMember[1] = 1000;
        _stakeDuplicateCommitteeMember[2] = 1000;
        _stakeDuplicateCommitteeMember[3] = 2002;
        _stakeDuplicateCommitteeMember[4] = 1000;

        address _committee = Upgrades.deployUUPSProxy("BridgeCommittee.sol", "", opts);

        committee = BridgeCommittee(_committee);

        vm.expectRevert(bytes("BridgeCommittee: Duplicate committee member"));

        committee.initialize(
            _committeeDuplicateCommitteeMember, _stakeDuplicateCommitteeMember, minStakeRequired
        );

        address[] memory _committeeNotSameLength = new address[](5);
        _committeeNotSameLength[0] = committeeMemberA;
        _committeeNotSameLength[1] = committeeMemberB;
        _committeeNotSameLength[2] = committeeMemberC;
        _committeeNotSameLength[3] = committeeMemberD;
        _committeeNotSameLength[4] = committeeMemberE;

        uint16[] memory _stakeNotSameLength = new uint16[](4);
        _stakeNotSameLength[0] = 1000;
        _stakeNotSameLength[1] = 1000;
        _stakeNotSameLength[2] = 1000;
        _stakeNotSameLength[3] = 2002;

        vm.expectRevert(
            bytes("BridgeCommittee: Committee and stake arrays must be of the same length")
        );

        committee.initialize(_committeeNotSameLength, _stakeNotSameLength, minStakeRequired);
    }

    function testVerifySignaturesWithValidSignatures() public {
        // Create a message
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.TOKEN_TRANSFER,
            version: 1,
            nonce: 1,
            chainID: chainID,
            payload: "0x0"
        });

        bytes memory messageBytes = BridgeUtils.encodeMessage(message);

        bytes32 messageHash = keccak256(messageBytes);

        bytes[] memory signatures = new bytes[](4);

        // Create signatures from A - D
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);

        // Call the verifySignatures function and it would not revert
        committee.verifySignatures(signatures, message);
    }

    function testVerifySignaturesWithInvalidSignatures() public {
        // Create a message with UPGRADE type which requires higher stake (5001)
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.UPGRADE,
            version: 1,
            nonce: 1,
            chainID: chainID,
            payload: hex"0000000000000000000000000000000000000000000000000000000000000000"
        });

        bytes memory messageBytes = BridgeUtils.encodeMessage(message);

        bytes32 messageHash = keccak256(messageBytes);

        bytes[] memory signatures = new bytes[](3);

        // Create signatures from A, B, C (stake: 1000+1000+1000=3000 < 5001 required)
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);

        // Call the verifySignatures function and expect it to revert due to insufficient stake
        vm.expectRevert(bytes("BridgeCommittee: Insufficient stake amount"));
        committee.verifySignatures(signatures, message);
    }

    function testVerifySignaturesDuplicateSignature() public {
        // Create a message
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.TOKEN_TRANSFER,
            version: 1,
            nonce: 1,
            chainID: chainID,
            payload: "0x0"
        });

        bytes memory messageBytes = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(messageBytes);

        bytes[] memory signatures = new bytes[](4);

        // Create signatures from A - C
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkA);
        signatures[2] = getSignature(messageHash, committeeMemberPkB);
        signatures[3] = getSignature(messageHash, committeeMemberPkC);

        // Call the verifySignatures function and expect it to revert
        vm.expectRevert(bytes("BridgeCommittee: Duplicate signature provided"));
        committee.verifySignatures(signatures, message);
    }

    function test_RevertWhen_UpdateBlocklistWithSignaturesInvalidNonce() public {
        // First, do a blocklist operation with nonce 0 to advance the nonce
        // Use committeeMemberB instead of A, so A can still sign later
        bytes memory payload0 = abi.encodePacked(uint8(0), uint8(1), committeeMemberB);
        BridgeUtils.Message memory message0 = BridgeUtils.Message({
            messageType: BridgeUtils.BLOCKLIST,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: payload0
        });
        bytes memory messageBytes0 = BridgeUtils.encodeMessage(message0);
        bytes32 messageHash0 = keccak256(messageBytes0);
        // Use A, C, D, E (not B since B is being blocklisted)
        bytes[] memory signatures0 = new bytes[](4);
        signatures0[0] = getSignature(messageHash0, committeeMemberPkA);
        signatures0[1] = getSignature(messageHash0, committeeMemberPkC);
        signatures0[2] = getSignature(messageHash0, committeeMemberPkD);
        signatures0[3] = getSignature(messageHash0, committeeMemberPkE);
        committee.updateBlocklistWithSignatures(signatures0, message0);

        // Now try to use nonce 0 again (invalid - should be 1)
        bytes memory payload = abi.encodePacked(uint8(1), uint8(1), committeeMemberB); // unblocklist B
        BridgeUtils.Message memory messageWrongNonce = BridgeUtils.Message({
            messageType: BridgeUtils.BLOCKLIST,
            version: 1,
            nonce: 0, // Wrong nonce - should be 1
            chainID: chainID,
            payload: payload
        });
        bytes memory messageBytes = BridgeUtils.encodeMessage(messageWrongNonce);
        bytes32 messageHash = keccak256(messageBytes);
        bytes[] memory signatures = new bytes[](4);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkC);
        signatures[2] = getSignature(messageHash, committeeMemberPkD);
        signatures[3] = getSignature(messageHash, committeeMemberPkE);
        vm.expectRevert(bytes("MessageVerifier: Invalid nonce"));
        committee.updateBlocklistWithSignatures(signatures, messageWrongNonce);
    }

    function testUpdateBlocklistWithSignaturesMessageDoesNotMatchType() public {
        // create payload with proper encoding: blocklistType(1) + membersLength(1) + address(20)
        bytes memory payload = abi.encodePacked(uint8(0), uint8(1), committeeMemberA);

        // Create a message with wrong messageType
        BridgeUtils.Message memory messageWrongMessageType = BridgeUtils.Message({
            messageType: BridgeUtils.TOKEN_TRANSFER,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: payload
        });
        bytes memory messageBytes = BridgeUtils.encodeMessage(messageWrongMessageType);
        bytes32 messageHash = keccak256(messageBytes);
        bytes[] memory signatures = new bytes[](4);

        // Create signatures from A - D
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);
        vm.expectRevert(bytes("MessageVerifier: message does not match type"));
        committee.updateBlocklistWithSignatures(signatures, messageWrongMessageType);
    }

    function test_RevertWhen_UpdateBlocklistWithSignaturesInvalidSignatures() public {
        // create payload with proper encoding: blocklistType(1) + membersLength(1) + address(20)
        bytes memory payload = abi.encodePacked(uint8(0), uint8(1), committeeMemberA);

        // Create a message
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.BLOCKLIST,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: payload
        });
        bytes memory messageBytes = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(messageBytes);
        bytes[] memory signatures = new bytes[](1);

        // Create signatures from A only (insufficient)
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        vm.expectRevert(bytes("BridgeCommittee: Insufficient stake amount"));
        committee.updateBlocklistWithSignatures(signatures, message);
    }

    function testAddToBlocklist() public {
        // create payload
        address[] memory _blocklist = new address[](1);
        _blocklist[0] = committeeMemberA;
        bytes memory payload = hex"0001";
        payload = abi.encodePacked(payload, committeeMemberA);

        // Create a message
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.BLOCKLIST,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: payload
        });

        bytes memory messageBytes = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(messageBytes);
        bytes[] memory signatures = new bytes[](4);

        // Create signatures from A - D
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);

        committee.updateBlocklistWithSignatures(signatures, message);

        assertTrue(committee.blocklist(committeeMemberA));

        // update message
        message.nonce = 1;
        // reconstruct signatures
        messageBytes = BridgeUtils.encodeMessage(message);
        messageHash = keccak256(messageBytes);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);
        // verify CommitteeMemberA's signature is no longer valid
        vm.expectRevert(bytes("BridgeCommittee: Signer is blocklisted"));
        // re-verify signatures
        committee.verifySignatures(signatures, message);
    }

    function testSignerNotCommitteeMember() public {
        // create payload
        bytes memory payload = abi.encode(committeeMemberA);

        // Create a message
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.UPGRADE,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: payload
        });

        bytes memory messageBytes = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(messageBytes);
        bytes[] memory signatures = new bytes[](4);

        (, uint256 committeeMemberPkF) = makeAddrAndKey("f");

        // Create signatures from A - D, and F
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkF);

        vm.expectRevert(bytes("BridgeCommittee: Signer has no stake"));
        committee.verifySignatures(signatures, message);
    }

    function testRemoveFromBlocklist() public {
        testAddToBlocklist();

        // create payload
        address[] memory _blocklist = new address[](1);
        _blocklist[0] = committeeMemberA;
        bytes memory payload = hex"0101";
        payload = abi.encodePacked(payload, committeeMemberA);

        // Create a message
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.BLOCKLIST,
            version: 1,
            nonce: 1,
            chainID: chainID,
            payload: payload
        });

        bytes memory messageBytes = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(messageBytes);
        bytes[] memory signatures = new bytes[](4);

        // Create signatures from B - E
        signatures[0] = getSignature(messageHash, committeeMemberPkB);
        signatures[1] = getSignature(messageHash, committeeMemberPkC);
        signatures[2] = getSignature(messageHash, committeeMemberPkD);
        signatures[3] = getSignature(messageHash, committeeMemberPkE);

        committee.updateBlocklistWithSignatures(signatures, message);

        // verify CommitteeMemberA is no longer blocklisted
        assertFalse(committee.blocklist(committeeMemberA));
    }

    // An e2e update committee blocklist regression test covering message ser/de
    function testUpdateCommitteeBlocklistRegressionTest() public {
        bytes memory payload =
            hex"010268b43fd906c0b8f024a18c56e06744f7c6157c65acaef39832cb995c4e049437a3e2ec6a7bad1ab5";
        // Create blocklist message
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.BLOCKLIST,
            version: 1,
            nonce: 68,
            chainID: 2,
            payload: payload
        });
        bytes memory encodedMessage = BridgeUtils.encodeMessage(message);
        bytes memory expectedEncodedMessage =
            hex"53544152434f494e5f4252494447455f4d4553534147450101000000000000004402010268b43fd906c0b8f024a18c56e06744f7c6157c65acaef39832cb995c4e049437a3e2ec6a7bad1ab5";

        assertEq(encodedMessage, expectedEncodedMessage);
    }

    // An e2e update committee blocklist regression test covering message ser/de and signature verification
    function testUpdateCommitteeBlocklistRegressionTestWithSignatures() public {
        address[] memory _committeeList = new address[](5);
        uint16[] memory _stake = new uint16[](5);
        uint8 chainID = 11;
        _committeeList[0] = committeeMemberA;
        _committeeList[1] = committeeMemberB;
        _committeeList[2] = committeeMemberC;
        _committeeList[3] = committeeMemberD;
        _committeeList[4] = committeeMemberE;
        _stake[0] = 1000;
        _stake[1] = 1000;
        _stake[2] = 1000;
        _stake[3] = 2002;
        _stake[4] = 4998;
        address _committee = Upgrades.deployUUPSProxy(
            "BridgeCommittee.sol",
            abi.encodeCall(BridgeCommittee.initialize, (_committeeList, _stake, minStakeRequired)),
            opts
        );
        committee = BridgeCommittee(_committee);

        address _config = Upgrades.deployUUPSProxy(
            "BridgeConfig.sol",
            abi.encodeCall(
                BridgeConfig.initialize,
                (address(committee), chainID, supportedTokens, tokenPrices, tokenIds, starcoinDecimals, supportedChains, 10)
            ),
            opts
        );

        committee.initializeConfig(_config);

        assertEq(committee.blocklist(committeeMemberA), false);

        // blocklist committeeMemberA
        bytes memory payload = abi.encodePacked(hex"0001", committeeMemberA);
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.BLOCKLIST,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: payload
        });
        bytes memory encodedMessage = BridgeUtils.encodeMessage(message);

        bytes32 messageHash = keccak256(encodedMessage);
        bytes[] memory signatures = new bytes[](4);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);

        committee.verifySignatures(signatures, message);
        committee.updateBlocklistWithSignatures(signatures, message);

        assertEq(committee.blocklist(committeeMemberA), true);

        // unblocklist committeeMemberA
        payload = abi.encodePacked(hex"0101", committeeMemberA);
        message = BridgeUtils.Message({
            messageType: BridgeUtils.BLOCKLIST,
            version: 1,
            nonce: 1,
            chainID: chainID,
            payload: payload
        });
        encodedMessage = BridgeUtils.encodeMessage(message);
        messageHash = keccak256(encodedMessage);

        signatures = new bytes[](4);
        // Note sig[0] is from blocklisted validator, and it does not count.
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);

        vm.expectRevert(bytes("BridgeCommittee: Signer is blocklisted"));
        committee.verifySignatures(signatures, message);

        // use sig from unblocklisted validators only (B, C, D, E)
        signatures = new bytes[](4);
        signatures[0] = getSignature(messageHash, committeeMemberPkB);
        signatures[1] = getSignature(messageHash, committeeMemberPkC);
        signatures[2] = getSignature(messageHash, committeeMemberPkD);
        signatures[3] = getSignature(messageHash, committeeMemberPkE);
        committee.verifySignatures(signatures, message);
        committee.updateBlocklistWithSignatures(signatures, message);
        assertEq(committee.blocklist(committeeMemberA), false);
    }

    /* ========== ADD MEMBER TESTS ========== */

    function testAddMemberWithSignatures() public {
        // Create a new member address
        address newMember = address(0x1234567890123456789012345678901234567890);
        uint16 stakeAmount = 500;

        // Create payload: 20 bytes address + 2 bytes stake
        bytes memory payload = abi.encodePacked(newMember, stakeAmount);

        // Create a message
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.ADD_MEMBER,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: payload
        });

        bytes memory messageBytes = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(messageBytes);
        bytes[] memory signatures = new bytes[](4);

        // Create signatures from A - D (need >5001 stake for ADD_MEMBER)
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);

        // Verify member doesn't exist
        assertEq(committee.committeeStake(newMember), 0);

        // Add the member
        committee.addMemberWithSignatures(signatures, message);

        // Verify member was added
        assertEq(committee.committeeStake(newMember), stakeAmount);
    }

    function testAddMemberWithSignaturesAlreadyExists() public {
        // Try to add an existing member (committeeMemberA)
        uint16 stakeAmount = 500;

        bytes memory payload = abi.encodePacked(committeeMemberA, stakeAmount);

        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.ADD_MEMBER,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: payload
        });

        bytes memory messageBytes = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(messageBytes);
        bytes[] memory signatures = new bytes[](4);

        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);

        // Should revert because member already exists
        vm.expectRevert(bytes("BridgeCommittee: Member already exists"));
        committee.addMemberWithSignatures(signatures, message);
    }

    function testAddMemberWithSignaturesInsufficientStake() public {
        address newMember = address(0x9876543210987654321098765432109876543210);
        uint16 stakeAmount = 500;

        bytes memory payload = abi.encodePacked(newMember, stakeAmount);

        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.ADD_MEMBER,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: payload
        });

        bytes memory messageBytes = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(messageBytes);
        bytes[] memory signatures = new bytes[](2);

        // Only 2 signatures (A + B = 2000 stake, need 5001)
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);

        // Should revert due to insufficient stake
        vm.expectRevert(bytes("BridgeCommittee: Insufficient stake amount"));
        committee.addMemberWithSignatures(signatures, message);
    }

    function testAddMemberWithSignaturesInvalidNonce() public {
        address newMember = address(0x1111222233334444555566667777888899990000);
        uint16 stakeAmount = 500;

        bytes memory payload = abi.encodePacked(newMember, stakeAmount);

        // Use wrong nonce (should be 0)
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.ADD_MEMBER,
            version: 1,
            nonce: 999,
            chainID: chainID,
            payload: payload
        });

        bytes memory messageBytes = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(messageBytes);
        bytes[] memory signatures = new bytes[](4);

        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);

        // Should revert due to invalid nonce
        vm.expectRevert(bytes("MessageVerifier: Invalid nonce"));
        committee.addMemberWithSignatures(signatures, message);
    }
}
