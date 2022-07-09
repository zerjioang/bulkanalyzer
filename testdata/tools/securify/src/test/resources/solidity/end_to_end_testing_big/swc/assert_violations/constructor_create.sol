/*
 * @source: ChainSecurity
 * @author: Anton Permenev
 */

pragma solidity ^0.5.0;

contract ConstructorCreate{
    B b = new B();

    function check() public {
        assert(b.foo() == 10);
    }

}

contract B{

    function foo() public returns(uint){
        return 11;
    }
}
