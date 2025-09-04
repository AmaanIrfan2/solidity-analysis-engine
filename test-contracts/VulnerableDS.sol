// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableStakingContract
 * @dev Intentionally contains multiple security vulnerabilities for testing tools
 * WARNING: DO NOT USE IN PRODUCTION - FOR SECURITY TESTING ONLY
 */
contract VulnerableStakingContract {
    // ============ STATE VARIABLES ============
    
    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;
    mapping(address => uint256) public lockTime;
    address[] private stakeholders;
    address public owner;
    uint256 public totalStaked;
    uint256 public REWARD_RATE = 10; // 10% reward rate
    bool private reentrancyLock;
    uint256 private constant MAX_UINT = 2**256 - 1;
    
    // ============ EVENTS ============
    
    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardPaid(address indexed user, uint256 reward);
    
    // ============ MODIFIERS ============
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner"); // Access control issue :cite[1]:cite[4]
        _;
    }
    
    // Ineffective reentrancy guard
    modifier noReentrant() {
        require(!reentrancyLock, "No reentrancy");
        reentrancyLock = true;
        _;
        reentrancyLock = false;
    }
    
    // ============ CONSTRUCTOR ============
    
    constructor() {
        owner = msg.sender;
        // Integer overflow potential if initialized with large value :cite[1]:cite[9]
        totalStaked = 0;
    }
    
    // ============ EXTERNAL FUNCTIONS ============
    
    /**
     * @dev Stake tokens into the contract
     * @param _amount Amount to stake
     */
    function stake(uint256 _amount) external {
        // Integer overflow vulnerability :cite[1]:cite[9]
        balances[msg.sender] += _amount;
        totalStaked += _amount;
        
        // Timestamp dependence :cite[1]:cite[4]
        lockTime[msg.sender] = block.timestamp + 30 days;
        
        // DOS with block gas limit :cite[1]:cite[4]
        stakeholders.push(msg.sender);
        
        emit Staked(msg.sender, _amount);
    }
    
    /**
     * @dev Withdraw staked tokens
     * @param _amount Amount to withdraw
     */
    function withdraw(uint256 _amount) external noReentrant {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        require(block.timestamp >= lockTime[msg.sender], "Tokens locked");
        
        // Reentrancy vulnerability - state change after external call :cite[1]:cite[9]
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");
        
        // Integer underflow vulnerability :cite[1]:cite[9]
        balances[msg.sender] -= _amount;
        totalStaked -= _amount;
        
        emit Withdrawn(msg.sender, _amount);
    }
    
    /**
     * @dev Calculate and claim rewards
     */
    function claimRewards() external {
        // Insecure randomness :cite[1]:cite[4]
        uint256 randomNumber = uint256(blockhash(block.number - 1)) % 100;
        
        // Logic error in reward calculation :cite[1]:cite[4]
        uint256 reward = (balances[msg.sender] * REWARD_RATE * randomNumber) / 100;
        
        // Front-running vulnerability - transparent calculation :cite[1]:cite[4]
        rewards[msg.sender] += reward;
        
        emit RewardPaid(msg.sender, reward);
    }
    
    /**
     * @dev Withdraw rewards
     */
    function withdrawRewards() external {
        uint256 reward = rewards[msg.sender];
        require(reward > 0, "No rewards");
        
        // Unchecked external call :cite[4]:cite[9]
        (bool success, ) = msg.sender.call{value: reward}("");
        
        // State change after external call without proper check
        rewards[msg.sender] = 0;
        
        emit RewardPaid(msg.sender, reward);
    }
    
    /**
     * @dev Admin function to add funds to contract
     */
    function addFunds() external payable onlyOwner {
        // No access control issue here, but in other functions
    }
    
    /**
     * @dev Dangerous function with tx.origin vulnerability :cite[9]
     */
    function transferOwnership(address newOwner) external {
        // Phishing with tx.origin :cite[9]
        require(tx.origin == owner, "Not authorized");
        owner = newOwner;
    }
    
    /**
     * @dev Function with integer overflow/underflow vulnerability
     */
    function calculatePercentage(uint256 value, uint256 percentage) public pure returns (uint256) {
        // Potential integer overflow :cite[1]:cite[9]
        return (value * percentage) / 100;
    }
    
    /**
     * @dev Function with denial of service vulnerability
     */
    function distributeRewards() external onlyOwner {
        // DOS through unbounded loop :cite[1]:cite[4]
        for (uint256 i = 0; i < stakeholders.length; i++) {
            address stakeholder = stakeholders[i];
            uint256 reward = (balances[stakeholder] * REWARD_RATE) / 100;
            rewards[stakeholder] += reward;
        }
    }
    
    /**
     * @dev Selfdestruct vulnerability (deprecated but included for testing) :cite[9]
     */
    function emergencyShutdown() external onlyOwner {
        // Deprecated selfdestruct function :cite[9]
        selfdestruct(payable(owner));
    }
    
    /**
     * @dev Function with incorrect visibility
     */
    function updateRewardRate(uint256 newRate) external {
        // Missing access control - should be onlyOwner :cite[1]:cite[4]
        REWARD_RATE = newRate;
    }
    
    /**
     * @dev Fallback function with reentrancy vulnerability
     */
    receive() external payable {
        // Potential reentrancy point :cite[1]:cite[9]
        if (msg.value > 0) {
            balances[msg.sender] += msg.value;
        }
    }
}
