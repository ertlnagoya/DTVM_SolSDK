pragma solidity ^0.8.0;
import "./fib_recur.sol";

contract FibonacciOffchain is FibonacciRecurTest {
    function _start() public pure {
        fibonacciTailOptimized(30);
    }
}
