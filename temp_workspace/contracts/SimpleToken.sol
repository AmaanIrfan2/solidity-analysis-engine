// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    
    constructor(uint256 _totalSupply) {
        totalSupply = _totalSupply;
        balances[msg.sender] = _totalSupply;
    }
    
    function transfer(address to, uint256 amount) public returns (bool) {
        balances[msg.sender] -= amount;  // Potential underflow - no check!
        balances[to] += amount;
        return true;
    }
    
    function batchTransfer(address[] memory recipients, uint256[] memory amounts) public {
        for (uint i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amounts[i];  // Gas: storage operation in loop
        }
    }
    
    function getBalance(address user) public view returns (uint256) {
        return balances[user];  // Multiple storage reads if called multiple times
    }
}
