// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/interfaces/IERC20Metadata.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./utils/CommitteeUpgradeable.sol";
import "./interfaces/IStarcoinBridge.sol";
import "./interfaces/IBridgeVault.sol";
import "./interfaces/IBridgeLimiter.sol";
import "./interfaces/IBridgeConfig.sol";

/// @title StarcoinBridge
/// @notice This contract implements a token bridge that enables users to deposit and withdraw
/// supported tokens to and from other chains. The bridge supports the transfer of Ethereum and ERC20
/// tokens. Bridge operations are managed by a committee of Starcoin validators that are responsible
/// for verifying and processing bridge messages. The bridge is designed to be upgradeable and
/// can be paused in case of an emergency. The bridge also enforces limits on the amount of
/// assets that can be withdrawn to prevent abuse.
contract StarcoinBridge is IStarcoinBridge, CommitteeUpgradeable, PausableUpgradeable {
    /* ========== STATE VARIABLES ========== */

    mapping(uint64 nonce => bool isProcessed) public isTransferProcessed;
    IBridgeVault public vault;
    IBridgeLimiter public limiter;

    // Starcoin uses 16-byte addresses (Move AccountAddress)
    uint8 constant STARCOIN_ADDRESS_LENGTH = 16;

    /// @notice Stores approval timestamp for transfers pending claim
    /// @dev Maps chainID => nonce => approval timestamp (0 means not approved)
    mapping(uint8 chainID => mapping(uint64 nonce => uint256 approvalTimestamp)) public transferApprovals;

    /// @notice Stores transfer details for approved transfers pending claim
    struct ApprovedTransfer {
        uint8 tokenID;
        address recipientAddress;
        uint256 erc20Amount;
        bytes senderAddress;
    }
    mapping(uint8 chainID => mapping(uint64 nonce => ApprovedTransfer)) public approvedTransfers;

    /* ========== INITIALIZER ========== */

    /// @notice Initializes the StarcoinBridge contract with the provided parameters.
    /// @dev this function should be called directly after deployment (see OpenZeppelin upgradeable standards).
    /// @param _committee The address of the committee contract.
    /// @param _vault The address of the bridge vault contract.
    /// @param _limiter The address of the bridge limiter contract.
    function initialize(address _committee, address _vault, address _limiter)
        external
        initializer
    {
        __CommitteeUpgradeable_init(_committee);
        __Pausable_init();
        vault = IBridgeVault(_vault);
        limiter = IBridgeLimiter(_limiter);
    }

    /* ========== EXTERNAL FUNCTIONS ========== */

    /// @notice Approves a token transfer with signatures. The transfer can be claimed after the delay period.
    /// @param signatures The array of signatures.
    /// @param message The BridgeUtils containing the transfer details.
    function approveTransferWithSignatures(
        bytes[] memory signatures,
        BridgeUtils.Message memory message
    )
        external
        nonReentrant
        verifyMessageAndSignatures(message, signatures, BridgeUtils.TOKEN_TRANSFER)
        onlySupportedChain(message.chainID)
    {
        // verify that message has not been processed
        require(!isTransferProcessed[message.nonce], "StarcoinBridge: Message already processed");
        require(transferApprovals[message.chainID][message.nonce] == 0, "StarcoinBridge: Transfer already approved");

        IBridgeConfig config = committee.config();

        BridgeUtils.TokenTransferPayload memory tokenTransferPayload =
            BridgeUtils.decodeTokenTransferPayload(message.payload);

        // verify target chain ID is this chain ID
        require(
            tokenTransferPayload.targetChain == config.chainID(), "StarcoinBridge: Invalid target chain"
        );

        // convert amount to ERC20 token decimals
        uint256 erc20AdjustedAmount = BridgeUtils.convertStarcoinToERC20Decimal(
            IERC20Metadata(config.tokenAddressOf(tokenTransferPayload.tokenID)).decimals(),
            config.tokenStarcoinDecimalOf(tokenTransferPayload.tokenID),
            tokenTransferPayload.amount
        );

        // Store approval with timestamp
        transferApprovals[message.chainID][message.nonce] = block.timestamp;
        approvedTransfers[message.chainID][message.nonce] = ApprovedTransfer({
            tokenID: tokenTransferPayload.tokenID,
            recipientAddress: tokenTransferPayload.recipientAddress,
            erc20Amount: erc20AdjustedAmount,
            senderAddress: tokenTransferPayload.senderAddress
        });

        emit TransferApproved(
            message.chainID,
            message.nonce,
            config.chainID(),
            tokenTransferPayload.tokenID,
            erc20AdjustedAmount,
            tokenTransferPayload.senderAddress,
            tokenTransferPayload.recipientAddress,
            block.timestamp
        );
    }

    /// @notice Claims an approved transfer after the delay period has passed.
    /// @param sourceChainID The source chain ID.
    /// @param nonce The nonce of the transfer to claim.
    function claimApprovedTransfer(uint8 sourceChainID, uint64 nonce)
        external
        nonReentrant
        whenNotPaused
    {
        require(!isTransferProcessed[nonce], "StarcoinBridge: Transfer already claimed");
        require(transferApprovals[sourceChainID][nonce] != 0, "StarcoinBridge: Transfer not approved");

        IBridgeConfig config = committee.config();
        uint256 approvalTime = transferApprovals[sourceChainID][nonce];
        uint64 delaySeconds = config.claimDelaySeconds();

        require(
            block.timestamp >= approvalTime + delaySeconds,
            "StarcoinBridge: Claim delay not passed"
        );

        ApprovedTransfer memory transfer = approvedTransfers[sourceChainID][nonce];

        _transferTokensFromVault(
            sourceChainID,
            transfer.tokenID,
            transfer.recipientAddress,
            transfer.erc20Amount
        );

        // mark message as processed
        isTransferProcessed[nonce] = true;

        // Clean up storage
        delete transferApprovals[sourceChainID][nonce];
        delete approvedTransfers[sourceChainID][nonce];

        emit TokensClaimed(
            sourceChainID,
            nonce,
            config.chainID(),
            transfer.tokenID,
            transfer.erc20Amount,
            transfer.senderAddress,
            transfer.recipientAddress
        );
    }

    /// @notice Executes an emergency operation with the provided signatures and message.
    /// @dev If the given operation is to freeze and the bridge is already frozen, the operation
    /// will revert.
    /// @param signatures The array of signatures to verify.
    /// @param message The BridgeUtils containing the details of the operation.
    function executeEmergencyOpWithSignatures(
        bytes[] memory signatures,
        BridgeUtils.Message memory message
    )
        external
        nonReentrant
        verifyMessageAndSignatures(message, signatures, BridgeUtils.EMERGENCY_OP)
    {
        // decode the emergency op message
        bool isFreezing = BridgeUtils.decodeEmergencyOpPayload(message.payload);

        if (isFreezing) _pause();
        else _unpause();

        emit EmergencyOperation(message.nonce, isFreezing);
    }

    /// @notice Enables the caller to deposit supported tokens to be bridged to a given
    /// destination chain.
    /// @dev The provided tokenID and destinationChainID must be supported. The caller must
    /// have approved this contract to transfer the given token.
    /// @param tokenID The ID of the token to be bridged.
    /// @param amount The amount of tokens to be bridged.
    /// @param recipientAddress The address on the Starcoin chain where the tokens will be sent.
    /// @param destinationChainID The ID of the destination chain.
    function bridgeERC20(
        uint8 tokenID,
        uint256 amount,
        bytes memory recipientAddress,
        uint8 destinationChainID
    ) external whenNotPaused nonReentrant onlySupportedChain(destinationChainID) {
        require(
            recipientAddress.length == STARCOIN_ADDRESS_LENGTH,
            "StarcoinBridge: Invalid recipient address length"
        );

        IBridgeConfig config = committee.config();

        require(config.isTokenSupported(tokenID), "StarcoinBridge: Unsupported token");

        address tokenAddress = config.tokenAddressOf(tokenID);

        // check that the bridge contract has allowance to transfer the tokens
        require(
            IERC20(tokenAddress).allowance(msg.sender, address(this)) >= amount,
            "StarcoinBridge: Insufficient allowance"
        );

        // calculate old vault balance
        uint256 oldBalance = IERC20(tokenAddress).balanceOf(address(vault));

        // Transfer the tokens from the contract to the vault
        SafeERC20.safeTransferFrom(IERC20(tokenAddress), msg.sender, address(vault), amount);

        // calculate new vault balance
        uint256 newBalance = IERC20(tokenAddress).balanceOf(address(vault));

        // calculate the amount transferred
        uint256 amountTransfered = newBalance - oldBalance;

        // Adjust the amount
        uint64 starcoinAdjustedAmount = BridgeUtils.convertERC20ToStarcoinDecimal(
            IERC20Metadata(tokenAddress).decimals(),
            config.tokenStarcoinDecimalOf(tokenID),
            amountTransfered
        );

        emit TokensDeposited(
            config.chainID(),
            nonces[BridgeUtils.TOKEN_TRANSFER],
            destinationChainID,
            tokenID,
            starcoinAdjustedAmount,
            msg.sender,
            recipientAddress
        );

        // increment token transfer nonce
        nonces[BridgeUtils.TOKEN_TRANSFER]++;
    }

    /// @notice Enables the caller to deposit Eth to be bridged to a given destination chain.
    /// @dev The provided destinationChainID must be supported.
    /// @param recipientAddress The address on the destination chain where Eth will be sent.
    /// @param destinationChainID The ID of the destination chain.
    function bridgeETH(bytes memory recipientAddress, uint8 destinationChainID)
        external
        payable
        whenNotPaused
        nonReentrant
        onlySupportedChain(destinationChainID)
    {
        require(
            recipientAddress.length == STARCOIN_ADDRESS_LENGTH,
            "StarcoinBridge: Invalid recipient address length"
        );

        uint256 amount = msg.value;

        // Transfer the unwrapped ETH to the target address
        (bool success,) = payable(address(vault)).call{value: amount}("");
        require(success, "StarcoinBridge: Failed to transfer ETH to vault");

        // Adjust the amount to emit.
        IBridgeConfig config = committee.config();

        // Adjust the amount
        uint64 starcoinAdjustedAmount = BridgeUtils.convertERC20ToStarcoinDecimal(
            IERC20Metadata(config.tokenAddressOf(BridgeUtils.ETH)).decimals(),
            config.tokenStarcoinDecimalOf(BridgeUtils.ETH),
            amount
        );

        emit TokensDeposited(
            config.chainID(),
            nonces[BridgeUtils.TOKEN_TRANSFER],
            destinationChainID,
            BridgeUtils.ETH,
            starcoinAdjustedAmount,
            msg.sender,
            recipientAddress
        );

        // increment token transfer nonce
        nonces[BridgeUtils.TOKEN_TRANSFER]++;
    }

    /* ========== INTERNAL FUNCTIONS ========== */

    /// @dev Transfers tokens from the vault to a target address.
    /// @param sendingChainID The ID of the chain from which the tokens are being transferred.
    /// @param tokenID The ID of the token being transferred.
    /// @param recipientAddress The address to which the tokens are being transferred.
    /// @param amount The amount of tokens being transferred.
    function _transferTokensFromVault(
        uint8 sendingChainID,
        uint8 tokenID,
        address recipientAddress,
        uint256 amount
    ) private whenNotPaused limitNotExceeded(sendingChainID, tokenID, amount) {
        address tokenAddress = committee.config().tokenAddressOf(tokenID);

        // Check that the token address is supported
        require(tokenAddress != address(0), "StarcoinBridge: Unsupported token");

        // transfer eth if token type is eth
        if (tokenID == BridgeUtils.ETH) {
            vault.transferETH(payable(recipientAddress), amount);
        } else {
            // transfer tokens from vault to target address
            vault.transferERC20(tokenAddress, recipientAddress, amount);
        }

        // update amount bridged
        limiter.recordBridgeTransfers(sendingChainID, tokenID, amount);
    }

    /* ========== MODIFIERS ========== */

    /// @dev Requires the amount being transferred does not exceed the bridge limit in
    /// the last 24 hours.
    /// @param tokenID The ID of the token being transferred.
    /// @param amount The amount of tokens being transferred.
    modifier limitNotExceeded(uint8 chainID, uint8 tokenID, uint256 amount) {
        require(
            !limiter.willAmountExceedLimit(chainID, tokenID, amount),
            "StarcoinBridge: Amount exceeds bridge limit"
        );
        _;
    }

    /// @dev Requires the target chain ID is supported.
    /// @param targetChainID The ID of the target chain.
    modifier onlySupportedChain(uint8 targetChainID) {
        require(
            committee.config().isChainSupported(targetChainID),
            "StarcoinBridge: Target chain not supported"
        );
        _;
    }
}
