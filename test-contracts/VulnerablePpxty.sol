
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19; // Using specific version to test pragma issues

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

// Vulnerable Contract with Multiple Security Issues
contract VulnerableEnterpriseContract is ERC20, Ownable {

    // State variables with various visibility issues
    uint256 private totalEtherBalance;
    uint256 public constant INITIAL_SUPPLY = 1000000 * 10**18;
    mapping(address => uint256) public userBalances;
    mapping(address => bool) public authorized;
    mapping(address => uint256) private secretBalances; // Unused state variable
    address[] public users;
    bool private initialized = false;
    uint256 private nonce = 0;

    // Events
    event Withdrawal(address indexed user, uint256 amount);
    event Deposit(address indexed user, uint256 amount);
    event RandomNumber(uint256 number);

    // Modifiers with vulnerabilities
    modifier onlyAuthorized() {
        require(authorized[msg.sender], "Not authorized");
        _;
    }

    modifier notContract() {
        require(tx.origin == msg.sender, "No contracts allowed"); // tx.origin vulnerability
        _;
    }

    // Constructor with vulnerabilities
    constructor() ERC20("VulnerableToken", "VULN") Ownable(msg.sender) {
        _mint(msg.sender, INITIAL_SUPPLY);
        initialized = true;
    }

    // SC01: Access Control Vulnerabilities
    function initializeContract() public {
        // Missing access control - anyone can call this
        initialized = true;
        authorized[msg.sender] = true;
    }

    function emergencyWithdraw() public {
        // Missing onlyOwner modifier
        payable(msg.sender).transfer(address(this).balance);
    }

    function setAuthorized(address user, bool status) public {
        // Missing access control
        authorized[user] = status;
    }

    // SC02: Price Oracle Manipulation (simulated)
    function getTokenPrice() public view returns (uint256) {
        // Using block.timestamp for price calculation - manipulable
        return (block.timestamp % 1000) + 100; // Predictable price
    }

    function swapTokens(uint256 tokenAmount) public {
        uint256 price = getTokenPrice();
        uint256 ethAmount = tokenAmount * price; // No slippage protection

        // Vulnerable to oracle manipulation
        require(address(this).balance >= ethAmount, "Insufficient contract balance");
        _burn(msg.sender, tokenAmount);
        payable(msg.sender).transfer(ethAmount);
    }

    // SC03: Logic Errors
    function distributeRewards() public {
        uint256 totalReward = address(this).balance;
        uint256 userCount = users.length;

        // Logic error: Division by zero not handled
        uint256 rewardPerUser = totalReward / userCount;

        for (uint256 i = 0; i < userCount; i++) {
            // Logic error: No bounds checking
            userBalances[users[i]] += rewardPerUser;
        }
    }

    function calculateFee(uint256 amount, uint256 feePercent) public pure returns (uint256) {
        // Logic error: No validation of feePercent
        return (amount * feePercent) / 100; // Can result in fees > amount
    }

    // SC04: Lack of Input Validation
    function transfer(address to, uint256 amount) public override returns (bool) {
        // No address validation
        // No amount validation
        return super.transfer(to, amount);
    }

    function setUserBalance(address user, uint256 balance) public {
        // No input validation
        userBalances[user] = balance;
    }

    function addUser(address user) public {
        // No duplicate checking
        users.push(user);
    }

    // SC05: Reentrancy Attacks
    function withdrawBalance() public {
        uint256 amount = userBalances[msg.sender];

        // External call before state change - classic reentrancy
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State change after external call
        userBalances[msg.sender] = 0;
        emit Withdrawal(msg.sender, amount);
    }

    function complexWithdraw(address recipient) public {
        uint256 amount = userBalances[msg.sender];

        // Multiple external calls
        payable(recipient).transfer(amount / 2);
        (bool success, ) = recipient.call{value: amount / 2}("");
        require(success, "Transfer failed");

        userBalances[msg.sender] = 0; // State change after external calls
    }

    // SC06: Unchecked External Calls
    function makeExternalCall(address target, bytes calldata data) public {
        // Unchecked low-level call
        target.call(data);
    }

    function batchTransfer(address[] memory recipients, uint256[] memory amounts) public {
        for (uint256 i = 0; i < recipients.length; i++) {
            // Unchecked external call in loop
            recipients[i].call{value: amounts[i]}("");
        }
    }

    function delegateToContract(address target, bytes calldata data) public {
        // Dangerous delegatecall
        target.delegatecall(data);
    }

    // SC07: Flash Loan Attack Simulation
    function flashLoan(uint256 amount) public {
        uint256 balanceBefore = address(this).balance;

        // Send tokens without proper checks
        payable(msg.sender).transfer(amount);

        // Vulnerable callback
        (bool success, ) = msg.sender.call(abi.encodeWithSignature("onFlashLoan(uint256)", amount));
        require(success, "Callback failed");

        // Insufficient validation of repayment
        require(address(this).balance >= balanceBefore, "Repayment failed");
    }

    // SC08: Integer Overflow and Underflow (using older patterns)
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        // Using unchecked block to demonstrate overflow
        unchecked {
            return a + b; // Can overflow
        }
    }

    function unsafeSub(uint256 a, uint256 b) public pure returns (uint256) {
        unchecked {
            return a - b; // Can underflow
        }
    }

    function vulnerableMint(address to, uint256 amount) public {
        // No checks for overflow in total supply
        unchecked {
            _mint(to, amount);
        }
    }

    // SC09: Insecure Randomness
    function generateRandomNumber() public returns (uint256) {
        // Predictable randomness using block properties
        uint256 randomNum = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.difficulty, // deprecated
            block.coinbase,
            nonce++
        ))) % 1000;

        emit RandomNumber(randomNum);
        return randomNum;
    }

    function lottery() public payable {
        require(msg.value > 0, "Must send ether");

        // Vulnerable random number generation
        uint256 winningNumber = uint256(keccak256(abi.encodePacked(
            blockhash(block.number - 1),
            msg.sender
        ))) % 10;

        if (winningNumber == 7) {
            payable(msg.sender).transfer(address(this).balance);
        }
    }

    // SC10: Denial of Service (DoS) Attacks
    function distributeToAll() public {
        // Unbounded loop - DoS vulnerability
        for (uint256 i = 0; i < users.length; i++) {
            // Gas limit can be reached
            payable(users[i]).transfer(1 ether);
        }
    }

    function processLargeArray(uint256[] memory data) public pure returns (uint256) {
        uint256 sum = 0;
        // Unbounded loop consuming gas
        for (uint256 i = 0; i < data.length; i++) {
            sum += data[i] * 2; // Expensive operation
        }
        return sum;
    }

    // Additional vulnerabilities for comprehensive testing

    // Timestamp dependence
    function timeBasedFunction() public {
        require(block.timestamp > 1640995200, "Too early"); // Hardcoded timestamp
        // Function logic depends on block.timestamp
    }

    // Weak PRNG
    function weakRandom() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp))) % 100;
    }

    // Unprotected self-destruct
    function destroy() public {
        // Missing access control
        selfdestruct(payable(msg.sender));
    }

    // Gas limit issues
    function expensiveLoop(uint256 iterations) public {
        for (uint256 i = 0; i < iterations; i++) {
            // Expensive operations
            keccak256(abi.encodePacked(i, block.timestamp));
        }
    }

    // Floating pragma (already demonstrated at top)

    // Assert usage
    function assertExample(uint256 value) public pure {
        assert(value != 0); // Should use require instead
    }

    // Deprecated functions
    function deprecatedFunction() public {
        // Using deprecated sha3 (would need to be uncommented to test)
        // bytes32 hash = sha3(abi.encodePacked("test"));

        // Using deprecated suicide (would need selfdestruct)
        // suicide(msg.sender);
    }

    // State variable shadowing
    uint256 ownerBalance; // Shadows Ownable's owner

    // Unused variables
    uint256 private unusedVariable;
    address private unusedAddress;

    // Function with complex fallback
    fallback() external payable {
        // Complex fallback function
        if (msg.data.length > 0) {
            address target = address(uint160(uint256(bytes32(msg.data[:20]))));
            target.delegatecall(msg.data[20:]);
        }
        totalEtherBalance += msg.value;
    }

    receive() external payable {
        totalEtherBalance += msg.value;
    }

    // Assembly usage
    function assemblyExample(uint256 x) public pure returns (uint256) {
        assembly {
            let result := add(x, 1)
            mstore(0x0, result)
            return(0x0, 32)
        }
    }

    // Missing events for critical functions
    function criticalFunction() public onlyOwner {
        initialized = false;
        // No event emitted
    }

    // Dangerous approval patterns
    function dangerousApproval(address spender) public {
        _approve(msg.sender, spender, type(uint256).max); // Unlimited approval
    }

    // Front-running vulnerability
    function frontRunVulnerable(uint256 bid) public payable {
        require(msg.value == bid, "Incorrect bid");
        // Vulnerable to front-running attacks
        if (bid > 1 ether) {
            payable(msg.sender).transfer(address(this).balance);
        }
    }
}

// Additional vulnerable contract for delegation pattern
contract VulnerableDelegate {
    address public owner;
    mapping(address => uint256) public balances;

    function initialize(address _owner) public {
        // Can be called multiple times
        owner = _owner;
    }

    function withdraw(uint256 amount) public {
        // Missing access control
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}

// Contract with unprotected initialize function
contract VulnerableUpgradeable {
    bool private initialized;
    address public admin;

    function initialize(address _admin) public {
        require(!initialized, "Already initialized");
        admin = _admin;
        initialized = true;
    }

    // Function that can be called before initialization
    function criticalFunction() public {
        // No initialization check
        // Critical logic here
    }
}