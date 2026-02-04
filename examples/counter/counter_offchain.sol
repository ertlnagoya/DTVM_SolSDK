pragma solidity ^0.8.0;
import "./counter.sol";

contract CounterOffchain is counter {
    function _start() public {
        setNoRevert(100);
    }
}
