// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BridgeBaseTest.t.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "../contracts/interfaces/IStarcoinBridge.sol";
import "./mocks/MockStarcoinBridgeV2.sol";

contract StarcoinBridgeTest is BridgeBaseTest, IStarcoinBridge {
    // This function is called before each unit test
    function setUp() public {
        setUpBridgeTest();
    }

    function testStarcoinBridgeInitialization() public {
        assertEq(address(bridge.committee()), address(committee));
        assertEq(address(bridge.vault()), address(vault));
    }

    function testApproveTransferTokenDailyLimitExceeded() public {
        uint8 senderAddressLength = 16;
        bytes memory senderAddress = hex"00000000000000000000000000000000";
        uint8 targetChain = chainID;
        uint8 recipientAddressLength = 20;
        address recipientAddress = bridgerA;
        uint8 tokenID = BridgeUtils.ETH;
        uint64 amount = 1_000_000 * USD_VALUE_MULTIPLIER;
        bytes memory payload = abi.encodePacked(
            senderAddressLength,
            senderAddress,
            targetChain,
            recipientAddressLength,
            recipientAddress,
            tokenID,
            amount
        );

        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.TOKEN_TRANSFER,
            version: 1,
            nonce: 1,
            chainID: 0,
            payload: payload
        });

        bytes memory encodedMessage = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);

        bytes[] memory signatures = new bytes[](4);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);

        // Approve should succeed
        bridge.approveTransferWithSignatures(signatures, message);

        // Advance time past delay
        skip(11);

        // Claim should revert due to daily limit
        vm.expectRevert(bytes("StarcoinBridge: Amount exceeds bridge limit"));
        bridge.claimApprovedTransfer(0, 1);
    }

    function testApproveTransferInvalidTargetChain() public {
        uint8 senderAddressLength = 16;
        bytes memory senderAddress = hex"00000000000000000000000000000000";
        uint8 targetChain = 0;
        uint8 recipientAddressLength = 20;
        address recipientAddress = bridgerA;
        uint8 tokenID = BridgeUtils.ETH;
        uint64 amount = 10000;
        bytes memory payload = abi.encodePacked(
            senderAddressLength,
            senderAddress,
            targetChain,
            recipientAddressLength,
            recipientAddress,
            tokenID,
            amount
        );

        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.TOKEN_TRANSFER,
            version: 1,
            nonce: 1,
            chainID: 1,
            payload: payload
        });

        bytes memory encodedMessage = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);

        bytes[] memory signatures = new bytes[](4);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);
        vm.expectRevert(bytes("StarcoinBridge: Target chain not supported"));
        bridge.approveTransferWithSignatures(signatures, message);
    }

    function testEmergencyOpInsufficientStakeAmount() public {
        // TOKEN_TRANSFER only requires 2 stake (any single member passes), so we test
        // insufficient stake using an unfreeze emergency op which requires 5001 stake.
        // Members A(1000) + B(1000) + C(1000) = 3000 < 5001 required for unfreeze.

        // unfreeze payload (isFreezing = false => opCode = 1)
        bytes memory payload = abi.encodePacked(uint8(1));

        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.EMERGENCY_OP,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: payload
        });

        bytes memory encodedMessage = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);

        // Only use A, B, C — total stake 3000 < 5001 (UNFREEZING_STAKE_REQUIRED)
        bytes[] memory signatures = new bytes[](3);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);

        vm.expectRevert(bytes("BridgeCommittee: Insufficient stake amount"));
        bridge.executeEmergencyOpWithSignatures(signatures, message);
    }

    function testApproveTransferMessageDoesNotMatchType() public {
        // Create transfer message
        BridgeUtils.TokenTransferPayload memory payload = BridgeUtils.TokenTransferPayload({
            senderAddressLength: 0,
            senderAddress: abi.encode(0),
            targetChain: 1,
            recipientAddressLength: 0,
            recipientAddress: bridgerA,
            tokenID: BridgeUtils.ETH,
            // This is Starcoin amount (eth decimal 8)
            amount: 100_000_000
        });
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.EMERGENCY_OP,
            version: 1,
            nonce: 1,
            chainID: chainID,
            payload: abi.encode(payload)
        });
        bytes memory encodedMessage = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        vm.expectRevert(bytes("MessageVerifier: message does not match type"));
        bridge.approveTransferWithSignatures(signatures, message);
    }

    function testTransferWETHWithValidSignatures() public {
        // Fill vault with WETH
        changePrank(deployer);
        IWETH9(wETH).deposit{value: 10 ether}();
        // IWETH9(wETH).withdraw(1 ether);
        IERC20(wETH).transfer(address(vault), 10 ether);
        // Create transfer payload
        uint8 senderAddressLength = 16;
        bytes memory senderAddress = hex"00000000000000000000000000000000";
        uint8 targetChain = chainID;
        uint8 recipientAddressLength = 20;
        address recipientAddress = bridgerA;
        uint8 tokenID = BridgeUtils.ETH;
        uint64 amount = 100000000; // 1 ether in starcoin decimals
        bytes memory payload = abi.encodePacked(
            senderAddressLength,
            senderAddress,
            targetChain,
            recipientAddressLength,
            recipientAddress,
            tokenID,
            amount
        );

        // Create transfer message
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.TOKEN_TRANSFER,
            version: 1,
            nonce: 1,
            chainID: 0,
            payload: payload
        });

        bytes memory encodedMessage = BridgeUtils.encodeMessage(message);

        bytes32 messageHash = keccak256(encodedMessage);

        bytes[] memory signatures = new bytes[](4);

        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);

        uint256 aBalance = bridgerA.balance;

        // Approve the transfer
        bridge.approveTransferWithSignatures(signatures, message);
        // Transfer should not be processed yet
        assertFalse(bridge.isTransferProcessed(1));

        // Advance time past the delay
        skip(11);

        // Claim the transfer
        bridge.claimApprovedTransfer(0, 1);
        assertEq(bridgerA.balance, aBalance + 1 ether);

        // Re-approving should revert
        vm.expectRevert(bytes("StarcoinBridge: Message already processed"));
        bridge.approveTransferWithSignatures(signatures, message);
    }

    function testTransferUSDCWithValidSignatures() public {
        // Fill vault with USDC using deal cheatcode
        deal(USDC, address(vault), 100_000_000);

        // Create transfer payload
        uint8 senderAddressLength = 16;
        bytes memory senderAddress = hex"00000000000000000000000000000000";
        uint8 targetChain = chainID;
        uint8 recipientAddressLength = 20;
        address recipientAddress = bridgerA;
        uint8 tokenID = BridgeUtils.USDC;
        uint64 amount = 1_000_000;
        bytes memory payload = abi.encodePacked(
            senderAddressLength,
            senderAddress,
            targetChain,
            recipientAddressLength,
            recipientAddress,
            tokenID,
            amount
        );

        // Create transfer message
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.TOKEN_TRANSFER,
            version: 1,
            nonce: 1,
            chainID: 0,
            payload: payload
        });

        bytes memory encodedMessage = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);

        bytes[] memory signatures = new bytes[](4);

        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);

        assert(IERC20(USDC).balanceOf(bridgerA) == 0);

        // Approve the transfer
        bridge.approveTransferWithSignatures(signatures, message);

        // Advance time past the delay
        skip(11);

        // Claim the transfer
        bridge.claimApprovedTransfer(0, 1);
        assert(IERC20(USDC).balanceOf(bridgerA) == 1_000_000);
    }

    function testExecuteEmergencyOpWithSignaturesInvalidOpCode() public {
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.EMERGENCY_OP,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: hex"02"
        });
        bytes memory encodedMessage = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);
        bytes[] memory signatures = new bytes[](4);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);
        vm.expectRevert(bytes("BridgeUtils: Invalid op code"));
        bridge.executeEmergencyOpWithSignatures(signatures, message);
    }

    function testExecuteEmergencyOpWithSignaturesInvalidNonce() public {
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.EMERGENCY_OP,
            version: 1,
            nonce: 1,
            chainID: chainID,
            payload: bytes(hex"00")
        });
        bytes memory encodedMessage = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);
        bytes[] memory signatures = new bytes[](4);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);
        vm.expectRevert(bytes("MessageVerifier: Invalid nonce"));
        bridge.executeEmergencyOpWithSignatures(signatures, message);
    }

    function testExecuteEmergencyOpWithSignaturesMessageDoesNotMatchType() public {
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.TOKEN_TRANSFER,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: abi.encode(0)
        });
        bytes memory encodedMessage = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);
        bytes[] memory signatures = new bytes[](4);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);
        vm.expectRevert(bytes("MessageVerifier: message does not match type"));
        bridge.executeEmergencyOpWithSignatures(signatures, message);
    }

    function testExecuteEmergencyOpWithSignaturesInvalidSignatures() public {
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.EMERGENCY_OP,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: bytes(hex"01")
        });
        bytes memory encodedMessage = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        vm.expectRevert(bytes("BridgeCommittee: Insufficient stake amount"));
        bridge.executeEmergencyOpWithSignatures(signatures, message);
    }

    function testFreezeBridgeEmergencyOp() public {
        // Create emergency op message
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.EMERGENCY_OP,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: bytes(hex"00")
        });

        bytes memory encodedMessage = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);

        bytes[] memory signatures = new bytes[](4);

        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);

        assertFalse(bridge.paused());
        bridge.executeEmergencyOpWithSignatures(signatures, message);
        assertTrue(bridge.paused());
    }

    function testUnfreezeBridgeEmergencyOp() public {
        testFreezeBridgeEmergencyOp();
        // Create emergency op message
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.EMERGENCY_OP,
            version: 1,
            nonce: 1,
            chainID: chainID,
            payload: bytes(hex"01")
        });

        bytes memory encodedMessage = BridgeUtils.encodeMessage(message);
        bytes32 messageHash = keccak256(encodedMessage);

        bytes[] memory signatures = new bytes[](4);

        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);

        bridge.executeEmergencyOpWithSignatures(signatures, message);
        assertFalse(bridge.paused());
    }

    function testBridgeERC20UnsupportedToken() public {
        vm.expectRevert(bytes("StarcoinBridge: Unsupported token"));
        bridge.bridgeERC20(
            255, 1 ether, hex"06bb77410cd326430fa2036c8282dbb5", 0
        );
    }

    function testBridgeERC20InsufficientAllowance() public {
        vm.expectRevert(bytes("StarcoinBridge: Insufficient allowance"));
        bridge.bridgeERC20(
            BridgeUtils.ETH,
            type(uint256).max,
            hex"06bb77410cd326430fa2036c8282dbb5",
            0
        );
    }

    function testBridgeERC20InvalidRecipientAddress() public {
        vm.expectRevert(bytes("StarcoinBridge: Invalid recipient address length"));
        bridge.bridgeERC20(
            BridgeUtils.ETH,
            1 ether,
            hex"06bb77410cd326430fa2036c8282dbb54a6f8640cea16ef5eff32d638718b3",
            0
        );
    }

    function testBridgeEthInvalidRecipientAddress() public {
        vm.expectRevert(bytes("StarcoinBridge: Invalid recipient address length"));
        bridge.bridgeETH{value: 1 ether}(
            hex"06bb77410cd326430fa2036c8282dbb54a6f8640cea16ef5eff32d638718b3", 0
        );
    }

    function testBridgeWETH() public {
        changePrank(deployer);
        IWETH9(wETH).deposit{value: 10 ether}();
        IERC20(wETH).approve(address(bridge), 10 ether);
        assertEq(IERC20(wETH).balanceOf(address(vault)), 0);
        uint256 balance = IERC20(wETH).balanceOf(deployer);

        // assert emitted event
        vm.expectEmit(true, true, true, false);
        emit TokensDeposited(
            chainID,
            0, // nonce
            0, // destination chain id
            BridgeUtils.ETH,
            1_00_000_000, // 1 ether
            deployer,
            hex"06bb77410cd326430fa2036c8282dbb5"
        );

        bridge.bridgeERC20(
            BridgeUtils.ETH,
            1 ether,
            hex"06bb77410cd326430fa2036c8282dbb5",
            0
        );
        assertEq(IERC20(wETH).balanceOf(address(vault)), 1 ether);
        assertEq(IERC20(wETH).balanceOf(deployer), balance - 1 ether);
        assertEq(bridge.nonces(BridgeUtils.TOKEN_TRANSFER), 1);

        // Now test rounding. For ETH, the last 10 digits are rounded
        vm.expectEmit(true, true, true, false);
        emit TokensDeposited(
            chainID,
            1, // nonce
            0, // destination chain id
            BridgeUtils.ETH,
            2.00000001 ether,
            deployer,
            hex"06bb77410cd326430fa2036c8282dbb5"
        );
        // 2_000_000_011_000_000_888 is rounded to 2.00000001 eth
        bridge.bridgeERC20(
            BridgeUtils.ETH,
            2_000_000_011_000_000_888,
            hex"06bb77410cd326430fa2036c8282dbb5",
            0
        );
        assertEq(IERC20(wETH).balanceOf(address(vault)), 3_000_000_011_000_000_888);
        assertEq(IERC20(wETH).balanceOf(deployer), balance - 3_000_000_011_000_000_888);
        assertEq(bridge.nonces(BridgeUtils.TOKEN_TRANSFER), 2);
    }

    function testBridgeUSDC() public {
        // Deal USDC to whale since mainnet balance may have changed
        deal(USDC, USDCWhale, 10_000_000);
        changePrank(USDCWhale);

        uint256 usdcAmount = 1000000;

        // approve
        IERC20(USDC).approve(address(bridge), usdcAmount);

        assertEq(IERC20(USDC).balanceOf(address(vault)), 0);
        uint256 balance = IERC20(USDC).balanceOf(USDCWhale);

        // assert emitted event
        vm.expectEmit(true, true, true, false);
        emit TokensDeposited(
            chainID,
            0, // nonce
            0, // destination chain id
            BridgeUtils.USDC,
            1_000_000, // 1 ether
            USDCWhale,
            hex"06bb77410cd326430fa2036c8282dbb5"
        );
        bridge.bridgeERC20(
            BridgeUtils.USDC,
            usdcAmount,
            hex"06bb77410cd326430fa2036c8282dbb5",
            0
        );

        assertEq(IERC20(USDC).balanceOf(USDCWhale), balance - usdcAmount);
        assertEq(IERC20(USDC).balanceOf(address(vault)), usdcAmount);
    }

    function testBridgeUSDT() public {
        // Deal USDT to whale since mainnet balance may have changed
        deal(USDT, USDTWhale, 10_000_000);
        changePrank(USDTWhale);

        uint256 usdtAmount = 1000000;

        // approve
        bytes4 selector = bytes4(keccak256("approve(address,uint256)"));
        bytes memory data = abi.encodeWithSelector(selector, address(bridge), usdtAmount);
        (bool success, bytes memory returnData) = USDT.call(data);
        require(success, "Call failed");

        assertEq(IERC20(USDT).balanceOf(address(vault)), 0);
        uint256 balance = IERC20(USDT).balanceOf(USDTWhale);

        // assert emitted event
        vm.expectEmit(true, true, true, false);
        emit TokensDeposited(
            chainID,
            0, // nonce
            0, // destination chain id
            BridgeUtils.USDT,
            1_000_000, // 1 ether
            USDTWhale,
            hex"06bb77410cd326430fa2036c8282dbb5"
        );
        bridge.bridgeERC20(
            BridgeUtils.USDT,
            usdtAmount,
            hex"06bb77410cd326430fa2036c8282dbb5",
            0
        );

        assertEq(IERC20(USDT).balanceOf(USDTWhale), balance - usdtAmount);
        assertEq(IERC20(USDT).balanceOf(address(vault)), usdtAmount);
    }

    function testBridgeBTC() public {
        // Deal wBTC to whale since mainnet balance may have changed
        deal(wBTC, wBTCWhale, 10_000_000);
        changePrank(wBTCWhale);

        uint256 wbtcAmount = 1000000;

        // approve
        IERC20(wBTC).approve(address(bridge), wbtcAmount);

        assertEq(IERC20(wBTC).balanceOf(address(vault)), 0);
        uint256 balance = IERC20(wBTC).balanceOf(wBTCWhale);

        // assert emitted event
        vm.expectEmit(true, true, true, false);
        emit TokensDeposited(
            chainID,
            0, // nonce
            0, // destination chain id
            BridgeUtils.BTC,
            1_000_000, // 1 ether
            wBTCWhale,
            hex"06bb77410cd326430fa2036c8282dbb5"
        );
        bridge.bridgeERC20(
            BridgeUtils.BTC,
            wbtcAmount,
            hex"06bb77410cd326430fa2036c8282dbb5",
            0
        );

        assertEq(IERC20(wBTC).balanceOf(wBTCWhale), balance - wbtcAmount);
        assertEq(IERC20(wBTC).balanceOf(address(vault)), wbtcAmount);
    }

    function testBridgeEth() public {
        changePrank(deployer);
        assertEq(IERC20(wETH).balanceOf(address(vault)), 0);
        uint256 balance = deployer.balance;

        // assert emitted event
        vm.expectEmit(true, true, true, false);
        emit IStarcoinBridge.TokensDeposited(
            chainID,
            0, // nonce
            0, // destination chain id
            BridgeUtils.ETH,
            1_000_000_00, // 1 ether
            deployer,
            hex"06bb77410cd326430fa2036c8282dbb5"
        );

        bridge.bridgeETH{value: 1 ether}(
            hex"06bb77410cd326430fa2036c8282dbb5", 0
        );
        assertEq(IERC20(wETH).balanceOf(address(vault)), 1 ether);
        assertEq(deployer.balance, balance - 1 ether);
        assertEq(bridge.nonces(BridgeUtils.TOKEN_TRANSFER), 1);
    }

    function testBridgeVaultReentrancy() public {
        changePrank(address(bridge));

        ReentrantAttack reentrantAttack = new ReentrantAttack(address(vault));
        vault.transferOwnership(address(reentrantAttack));
        // Fill vault with WETH
        changePrank(deployer);
        IWETH9(wETH).deposit{value: 10 ether}();
        IERC20(wETH).transfer(address(vault), 10 ether);
        vm.expectRevert("ETH transfer failed");
        reentrantAttack.attack();
    }

    function testStarcoinBridgeInvalidERC20DecimalConversion() public {
        IERC20(wETH).approve(address(bridge), 10 ether);
        vm.expectRevert(bytes("BridgeUtils: Insufficient amount provided"));
        bridge.bridgeERC20(
            BridgeUtils.ETH,
            1,
            hex"06bb77410cd326430fa2036c8282dbb5",
            0
        );
    }

    function testStarcoinBridgeInvalidEthDecimalConversion() public {
        vm.expectRevert(bytes("BridgeUtils: Insufficient amount provided"));
        bridge.bridgeETH{value: 1}(
            hex"06bb77410cd326430fa2036c8282dbb5", 0
        );
    }

    function testStarcoinBridgeInvalidERC20Transfer() public {
        vm.expectRevert(bytes("BridgeUtils: Insufficient amount provided"));
        bridge.bridgeERC20(
            BridgeUtils.USDC,
            0,
            hex"06bb77410cd326430fa2036c8282dbb5",
            0
        );
    }

    function testStarcoinBridgeInvalidETHTransfer() public {
        vm.expectRevert(bytes("BridgeUtils: Insufficient amount provided"));
        bridge.bridgeETH{value: 0}(
            hex"06bb77410cd326430fa2036c8282dbb5", 0
        );
    }

    // An e2e token transfer regression test covering message ser/de and signature verification
    function testTransferStarcoinToEthRegressionTest() public {
        address[] memory _committeeList = new address[](5);
        uint16[] memory _stake = new uint16[](5);
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

        vault = new BridgeVault(wETH);
        tokenPrices = new uint64[](5);
        tokenPrices[0] = 1 * USD_VALUE_MULTIPLIER; // STC PRICE
        tokenPrices[1] = 1 * USD_VALUE_MULTIPLIER; // BTC PRICE
        tokenPrices[2] = 1 * USD_VALUE_MULTIPLIER; // ETH PRICE
        tokenPrices[3] = 1 * USD_VALUE_MULTIPLIER; // USDC PRICE
        tokenPrices[4] = 1 * USD_VALUE_MULTIPLIER; // USDT PRICE

        // deploy bridge config with 11 chainID
        address[] memory _supportedTokens = new address[](5);
        _supportedTokens[0] = address(0);
        _supportedTokens[1] = wBTC;
        _supportedTokens[2] = wETH;
        _supportedTokens[3] = USDC;
        _supportedTokens[4] = USDT;
        uint8 supportedChainID = 1;
        uint8[] memory _supportedDestinationChains = new uint8[](1);
        _supportedDestinationChains[0] = 1;

        address _config = Upgrades.deployUUPSProxy(
            "BridgeConfig.sol",
            abi.encodeCall(
                BridgeConfig.initialize,
                (address(committee), 11, _supportedTokens, tokenPrices, tokenIds, starcoinDecimals, _supportedDestinationChains, 10)
            ),
            opts
        );

        committee.initializeConfig(_config);

        skip(2 days);

        uint64[] memory totalLimits = new uint64[](1);
        totalLimits[0] = 100 * USD_VALUE_MULTIPLIER;

        address _limiter = Upgrades.deployUUPSProxy(
            "BridgeLimiter.sol",
            abi.encodeCall(
                BridgeLimiter.initialize,
                (address(committee), _supportedDestinationChains, totalLimits)
            ),
            opts
        );
        limiter = BridgeLimiter(_limiter);
        address _StarcoinBridge = Upgrades.deployUUPSProxy(
            "StarcoinBridge.sol",
            abi.encodeCall(
                StarcoinBridge.initialize, (address(committee), address(vault), address(limiter))
            ),
            opts
        );
        bridge = StarcoinBridge(_StarcoinBridge);

        vault.transferOwnership(address(bridge));
        limiter.transferOwnership(address(bridge));

        // Fill vault with WETH
        changePrank(deployer);
        IWETH9(wETH).deposit{value: 10 ether}();
        IERC20(wETH).transfer(address(vault), 10 ether);
        address recipientAddress = 0xb18f79Fe671db47393315fFDB377Da4Ea1B7AF96;

        bytes memory payload =
            hex"1080ab1ee086210a3a37355300ca24672e0b14b18f79fe671db47393315ffdb377da4ea1b7af960200000000000186a0";
        // Create transfer message
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.TOKEN_TRANSFER,
            version: 1,
            nonce: 1,
            chainID: supportedChainID,
            payload: payload
        });
        bytes memory encodedMessage = BridgeUtils.encodeMessage(message);
        bytes memory expectedEncodedMessage =
            hex"53544152434f494e5f4252494447455f4d45535341474500010000000000000001011080ab1ee086210a3a37355300ca24672e0b14b18f79fe671db47393315ffdb377da4ea1b7af960200000000000186a0";

        assertEq(encodedMessage, expectedEncodedMessage);

        bytes32 messageHash = keccak256(encodedMessage);
        bytes[] memory signatures = new bytes[](4);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);

        uint256 aBalance = recipientAddress.balance;
        committee.verifySignatures(signatures, message);

        // Approve the transfer
        bridge.approveTransferWithSignatures(signatures, message);

        // Advance time past the delay
        skip(11);

        // Claim the transfer
        bridge.claimApprovedTransfer(supportedChainID, 1);
        assertEq(recipientAddress.balance, aBalance + 0.001 ether);
    }

    // An e2e emergency op regression test covering message ser/de
    function testEmergencyOpRegressionTest() public {
        address[] memory _committeeList = new address[](4);
        uint16[] memory _stake = new uint16[](4);
        _committeeList[0] = 0x68B43fD906C0B8F024a18C56e06744F7c6157c65;
        _committeeList[1] = 0xaCAEf39832CB995c4E049437A3E2eC6a7bad1Ab5;
        _committeeList[2] = 0x8061f127910e8eF56F16a2C411220BaD25D61444;
        _committeeList[3] = 0x508F3F1ff45F4ca3D8e86CDCC91445F00aCC59fC;
        _stake[0] = 2500;
        _stake[1] = 2500;
        _stake[2] = 2500;
        _stake[3] = 2500;
        address _committee = Upgrades.deployUUPSProxy(
            "BridgeCommittee.sol",
            abi.encodeCall(BridgeCommittee.initialize, (_committeeList, _stake, minStakeRequired)),
            opts
        );
        committee = BridgeCommittee(_committee);

        vault = new BridgeVault(wETH);
        tokenPrices = new uint64[](5);
        tokenPrices[0] = 1 * USD_VALUE_MULTIPLIER; // STC PRICE
        tokenPrices[1] = 1 * USD_VALUE_MULTIPLIER; // BTC PRICE
        tokenPrices[2] = 1 * USD_VALUE_MULTIPLIER; // ETH PRICE
        tokenPrices[3] = 1 * USD_VALUE_MULTIPLIER; // USDC PRICE
        tokenPrices[4] = 1 * USD_VALUE_MULTIPLIER; // USDT PRICE
        uint8 _chainID = 2;
        uint8[] memory _supportedDestinationChains = new uint8[](1);
        _supportedDestinationChains[0] = 0;
        address[] memory _supportedTokens = new address[](5);
        _supportedTokens[0] = address(0);
        _supportedTokens[1] = wBTC;
        _supportedTokens[2] = wETH;
        _supportedTokens[3] = USDC;
        _supportedTokens[4] = USDT;

        address _config = Upgrades.deployUUPSProxy(
            "BridgeConfig.sol",
            abi.encodeCall(
                BridgeConfig.initialize,
                (
                    address(committee),
                    _chainID,
                    _supportedTokens,
                    tokenPrices,
                    tokenIds,
                    starcoinDecimals,
                    _supportedDestinationChains,
                    10
                )
            ),
            opts
        );

        config = BridgeConfig(_config);

        committee.initializeConfig(address(config));

        uint64[] memory totalLimits = new uint64[](1);
        totalLimits[0] = 100 * USD_VALUE_MULTIPLIER;
        skip(2 days);

        address _limiter = Upgrades.deployUUPSProxy(
            "BridgeLimiter.sol",
            abi.encodeCall(
                BridgeLimiter.initialize,
                (address(committee), _supportedDestinationChains, totalLimits)
            ),
            opts
        );

        limiter = BridgeLimiter(_limiter);

        address _StarcoinBridge = Upgrades.deployUUPSProxy(
            "StarcoinBridge.sol",
            abi.encodeCall(
                StarcoinBridge.initialize, (address(committee), address(vault), address(limiter))
            ),
            opts
        );

        bridge = StarcoinBridge(_StarcoinBridge);

        bytes memory payload = hex"00";
        // Create emergency op message
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.EMERGENCY_OP,
            version: 1,
            nonce: 55,
            chainID: _chainID,
            payload: payload
        });
        bytes memory encodedMessage = BridgeUtils.encodeMessage(message);
        bytes memory expectedEncodedMessage =
            hex"53544152434f494e5f4252494447455f4d455353414745020100000000000000370200";

        assertEq(encodedMessage, expectedEncodedMessage);
    }

    // An e2e emergency op regression test covering message ser/de and signature verification
    function testEmergencyOpRegressionTestWithSigVerification() public {
        address[] memory _committeeList = new address[](5);
        _committeeList[0] = committeeMemberA;
        _committeeList[1] = committeeMemberB;
        _committeeList[2] = committeeMemberC;
        _committeeList[3] = committeeMemberD;
        _committeeList[4] = committeeMemberE;
        uint16[] memory _stake = new uint16[](5);
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

        uint8 chainID = 11;

        address _config = Upgrades.deployUUPSProxy(
            "BridgeConfig.sol",
            abi.encodeCall(
                BridgeConfig.initialize,
                (address(committee), chainID, supportedTokens, tokenPrices, tokenIds, starcoinDecimals, supportedChains, 10)
            ),
            opts
        );

        committee.initializeConfig(address(_config));

        vault = new BridgeVault(wETH);

        uint64[] memory totalLimits = new uint64[](1);
        totalLimits[0] = 100 * USD_VALUE_MULTIPLIER;

        skip(2 days);

        address _limiter = Upgrades.deployUUPSProxy(
            "BridgeLimiter.sol",
            abi.encodeCall(
                BridgeLimiter.initialize, (address(committee), supportedChains, totalLimits)
            ),
            opts
        );
        limiter = BridgeLimiter(_limiter);

        address _StarcoinBridge = Upgrades.deployUUPSProxy(
            "StarcoinBridge.sol",
            abi.encodeCall(
                StarcoinBridge.initialize, (address(committee), address(vault), address(limiter))
            ),
            opts
        );
        bridge = StarcoinBridge(_StarcoinBridge);

        assertFalse(bridge.paused());

        // pause
        bytes memory payload = hex"00";
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.EMERGENCY_OP,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: payload
        });
        bytes memory encodedMessage = BridgeUtils.encodeMessage(message);
        bytes memory expectedEncodedMessage =
            hex"53544152434f494e5f4252494447455f4d455353414745020100000000000000000b00";

        assertEq(encodedMessage, expectedEncodedMessage);

        bytes32 messageHash = keccak256(encodedMessage);
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = getSignature(messageHash, committeeMemberPkE);

        bridge.executeEmergencyOpWithSignatures(signatures, message);
        assertTrue(bridge.paused());

        // unpause
        payload = hex"01";
        message = BridgeUtils.Message({
            messageType: BridgeUtils.EMERGENCY_OP,
            version: 1,
            nonce: 1,
            chainID: chainID,
            payload: payload
        });
        encodedMessage = BridgeUtils.encodeMessage(message);
        expectedEncodedMessage = hex"53544152434f494e5f4252494447455f4d455353414745020100000000000000010b01";

        assertEq(encodedMessage, expectedEncodedMessage);

        messageHash = keccak256(encodedMessage);
        // Unfreeze requires 5001 stake - A(1000)+B(1000)+C(1000)+D(2002)=5002 >= 5001
        signatures = new bytes[](4);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);

        bridge.executeEmergencyOpWithSignatures(signatures, message);
        assertFalse(bridge.paused());

        // reusing the sig from nonce 0 will revert
        payload = hex"00";
        message = BridgeUtils.Message({
            messageType: BridgeUtils.EMERGENCY_OP,
            version: 1,
            nonce: 0,
            chainID: chainID,
            payload: payload
        });

        encodedMessage = BridgeUtils.encodeMessage(message);
        messageHash = keccak256(encodedMessage);
        signatures = new bytes[](1);
        signatures[0] = getSignature(messageHash, committeeMemberPkE);

        vm.expectRevert(bytes("MessageVerifier: Invalid nonce"));
        bridge.executeEmergencyOpWithSignatures(signatures, message);

        assertFalse(bridge.paused());
    }

    // An e2e upgrade regression test covering message ser/de and signature verification
    function testUpgradeRegressionTest() public {
        address[] memory _committeeList = new address[](4);
        uint16[] memory _stake = new uint16[](4);
        _committeeList[0] = 0x68B43fD906C0B8F024a18C56e06744F7c6157c65;
        _committeeList[1] = 0xaCAEf39832CB995c4E049437A3E2eC6a7bad1Ab5;
        _committeeList[2] = 0x8061f127910e8eF56F16a2C411220BaD25D61444;
        _committeeList[3] = 0x508F3F1ff45F4ca3D8e86CDCC91445F00aCC59fC;
        _stake[0] = 2500;
        _stake[1] = 2500;
        _stake[2] = 2500;
        _stake[3] = 2500;

        address _committee = Upgrades.deployUUPSProxy(
            "BridgeCommittee.sol",
            abi.encodeCall(BridgeCommittee.initialize, (_committeeList, _stake, minStakeRequired)),
            opts
        );

        committee = BridgeCommittee(_committee);

        vault = new BridgeVault(wETH);
        tokenPrices = new uint64[](5);
        tokenPrices[0] = 1 * USD_VALUE_MULTIPLIER; // STC PRICE
        tokenPrices[1] = 1 * USD_VALUE_MULTIPLIER; // BTC PRICE
        tokenPrices[2] = 1 * USD_VALUE_MULTIPLIER; // ETH PRICE
        tokenPrices[3] = 1 * USD_VALUE_MULTIPLIER; // USDC PRICE
        tokenPrices[4] = 1 * USD_VALUE_MULTIPLIER; // USDT PRICE
        uint8 _chainID = 12;
        uint8[] memory _supportedDestinationChains = new uint8[](1);
        _supportedDestinationChains[0] = 0;
        address[] memory _supportedTokens = new address[](5);
        _supportedTokens[0] = address(0);
        _supportedTokens[1] = wBTC;
        _supportedTokens[2] = wETH;
        _supportedTokens[3] = USDC;
        _supportedTokens[4] = USDT;

        address _config = Upgrades.deployUUPSProxy(
            "BridgeConfig.sol",
            abi.encodeCall(
                BridgeConfig.initialize,
                (
                    address(committee),
                    _chainID,
                    _supportedTokens,
                    tokenPrices,
                    tokenIds,
                    starcoinDecimals,
                    _supportedDestinationChains,
                    10
                )
            ),
            opts
        );

        committee.initializeConfig(_config);

        skip(2 days);
        uint64[] memory totalLimits = new uint64[](1);
        totalLimits[0] = 1_000_000 * USD_VALUE_MULTIPLIER;
        address _limiter = Upgrades.deployUUPSProxy(
            "BridgeLimiter.sol",
            abi.encodeCall(
                BridgeLimiter.initialize,
                (address(committee), _supportedDestinationChains, totalLimits)
            ),
            opts
        );
        limiter = BridgeLimiter(_limiter);
        address _StarcoinBridge = Upgrades.deployUUPSProxy(
            "StarcoinBridge.sol",
            abi.encodeCall(
                StarcoinBridge.initialize, (address(committee), address(vault), address(limiter))
            ),
            opts
        );
        bridge = StarcoinBridge(_StarcoinBridge);
        vault.transferOwnership(address(bridge));
        limiter.transferOwnership(address(bridge));

        // Fill vault with WETH
        changePrank(deployer);
        IWETH9(wETH).deposit{value: 10 ether}();
        IERC20(wETH).transfer(address(vault), 10 ether);

        bytes memory payload =
            hex"00000000000000000000000006060606060606060606060606060606060606060000000000000000000000000909090909090909090909090909090909090909000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000045cd8a76b00000000000000000000000000000000000000000000000000000000";
        // Create transfer message
        BridgeUtils.Message memory message = BridgeUtils.Message({
            messageType: BridgeUtils.UPGRADE,
            version: 1,
            nonce: 123,
            chainID: _chainID,
            payload: payload
        });
        bytes memory encodedMessage = BridgeUtils.encodeMessage(message);
        bytes memory expectedEncodedMessage =
            hex"53544152434f494e5f4252494447455f4d4553534147450501000000000000007b0c00000000000000000000000006060606060606060606060606060606060606060000000000000000000000000909090909090909090909090909090909090909000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000045cd8a76b00000000000000000000000000000000000000000000000000000000";

        assertEq(encodedMessage, expectedEncodedMessage);

        (address proxy, address newImp, bytes memory _calldata) =
            BridgeUtils.decodeUpgradePayload(payload);

        assertEq(proxy, address(0x0606060606060606060606060606060606060606));
        assertEq(newImp, address(0x0909090909090909090909090909090909090909));
        assertEq(_calldata, hex"5cd8a76b");
    }

    // ============ Claim Delay Tests ============

    // Helper function to create a transfer message and signatures
    function _createTransferMessageAndSigs(uint64 nonce)
        internal
        view
        returns (BridgeUtils.Message memory message, bytes[] memory signatures)
    {
        bytes memory payload = abi.encodePacked(
            uint8(16), // senderAddressLength
            hex"06bb77410cd326430fa2036c8282dbb5", // senderAddress
            chainID, // targetChain
            uint8(20), // recipientAddressLength
            bridgerA, // recipientAddress
            BridgeUtils.ETH, // tokenID
            uint64(100000000) // amount: 1 ether in starcoin decimals
        );

        message = BridgeUtils.Message({
            messageType: BridgeUtils.TOKEN_TRANSFER,
            version: 1,
            nonce: nonce,
            chainID: 0,
            payload: payload
        });

        bytes32 messageHash = keccak256(BridgeUtils.encodeMessage(message));

        signatures = new bytes[](4);
        signatures[0] = getSignature(messageHash, committeeMemberPkA);
        signatures[1] = getSignature(messageHash, committeeMemberPkB);
        signatures[2] = getSignature(messageHash, committeeMemberPkC);
        signatures[3] = getSignature(messageHash, committeeMemberPkD);
    }

    function _fillVaultWithWETH() internal {
        changePrank(deployer);
        IWETH9(wETH).deposit{value: 10 ether}();
        IERC20(wETH).transfer(address(vault), 10 ether);
    }

    function testClaimNotApproved() public {
        vm.expectRevert(bytes("StarcoinBridge: Transfer not approved"));
        bridge.claimApprovedTransfer(0, 999);
    }
}

contract ReentrantAttack {
    IBridgeVault public vault;
    bool private attackInitiated;

    constructor(address _vault) {
        vault = IBridgeVault(_vault);
    }

    receive() external payable {
        if (!attackInitiated) {
            attackInitiated = true;
            vault.transferETH(payable(address(this)), 100);
        }
    }

    function attack() external payable {
        attackInitiated = false;
        vault.transferETH(payable(address(this)), 100);
    }
}
