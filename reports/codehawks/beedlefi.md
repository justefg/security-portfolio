# Beedle - Oracle free perpetual lending - Findings Report

# Table of contents
- [Beedle - Oracle free perpetual lending - Findings Report](#beedle---oracle-free-perpetual-lending---findings-report)
- [Table of contents](#table-of-contents)
- [Contest Summary](#contest-summary)
    - [Sponsor: BeedleFi](#sponsor-beedlefi)
    - [Dates: Jul 24th, 2023 - Aug 7th, 2023](#dates-jul-24th-2023---aug-7th-2023)
- [Results Summary](#results-summary)
    - [Number of findings:](#number-of-findings)
- [High Risk Findings](#high-risk-findings)
  - [H-01. borrower can sweep the pool entirely when loanToken and collateral have different precision](#h-01-borrower-can-sweep-the-pool-entirely-when-loantoken-and-collateral-have-different-precision)
  - [H-02. Missing check for transfer and transferFrom() return values](#h-02-missing-check-for-transfer-and-transferfrom-return-values)
  - [H-03. The contract's funds can be drained entirely](#h-03-the-contracts-funds-can-be-drained-entirely)
  - [H-04. Attacker can drain all balance of ERC777 tokens](#h-04-attacker-can-drain-all-balance-of-erc777-tokens)
  - [H-05. Staker contract can be drained entirely via claim](#h-05-staker-contract-can-be-drained-entirely-via-claim)
  - [H-06. Missing approve will result in a failed swap](#h-06-missing-approve-will-result-in-a-failed-swap)
- [Medium Risk Findings](#medium-risk-findings)
  - [M-01. Attacker can DoS manager from removing funds from the pool](#m-01-attacker-can-dos-manager-from-removing-funds-from-the-pool)
  - [M-02. Pool manager can hike interest rates without user knowing](#m-02-pool-manager-can-hike-interest-rates-without-user-knowing)
  - [M-03. Make MAX\_AUCTION\_LENGTH modifiable to adjust for changing market conditions](#m-03-make-max_auction_length-modifiable-to-adjust-for-changing-market-conditions)
  - [M-04. Attacker can stop staking contract from paying rewards](#m-04-attacker-can-stop-staking-contract-from-paying-rewards)
  - [M-05. UniswapV3 incorrect swap parameters will result in a swap failure and swap at a bad rate](#m-05-uniswapv3-incorrect-swap-parameters-will-result-in-a-swap-failure-and-swap-at-a-bad-rate)
- [Gas Optimizations / Informationals](#gas-optimizations--informationals)
  - [G/I-01. Missing length equality check for loanIds and poolIds](#gi-01-missing-length-equality-check-for-loanids-and-poolids)

# <a id='contest-summary'></a>Contest Summary

### Sponsor: BeedleFi

### Dates: Jul 24th, 2023 - Aug 7th, 2023

[See more contest details here](https://www.codehawks.com/contests/clkbo1fa20009jr08nyyf9wbx)

# <a id='results-summary'></a>Results Summary

### Number of findings:
   - High: 6
   - Medium: 5
   - Low: 0
  - Gas/Info: 1

# High Risk Findings

## <a id='H-01'></a>H-01. borrower can sweep the pool entirely when loanToken and collateral have different precision



The formulaes should be adjusted for token precision differences

https://github.com/Cyfrin/2023-07-beedle/blob/main/src/Lender.sol#L246

https://github.com/Cyfrin/2023-07-beedle/blob/main/src/Lender.sol#L384

https://github.com/Cyfrin/2023-07-beedle/blob/main/src/Lender.sol#L618

maxLoanRatio is not respected when loanToken and collateral have different precisions, i.e
loanToken is wbtc and collateralToken is weth

uint256 loanRatio = (debt * 10 ** 18) / collateral

It's not clearly stated how maxLoanRatio translates to percentages but protocol developers use 10 ** 18 in the tests a lot.

In the case of WBTC and WETH the result will be much smaller than 10 ** 18 which allows an attacker to steal the funds.

Mitigation steps:

uint constant BPS = 10000;

uint256 loanRatio = (debt * 10 ** collateral.precision() * BPS) / (collateral * debt.precision());

## <a id='H-02'></a>H-02. Missing check for transfer and transferFrom() return values



Some tokens don't implement EIP20 correctly which means they don't revert on failed transfers. Examples include but aren't limited to USDT, EURS and BAT.

https://etherscan.io/token/0xdb25f211ab05b1c97d595516f45794528a807ad8#code

https://etherscan.io/token/0x0d8775f648430679a709e98d2b0cb6250d2887ef#code

This will allow pool managers and borrowers to participate in the lending / borrowing without having required funds.

Mitigation steps:

Check transfer and transferFrom return values

Use safeERC20.sol library from openzepplin
## <a id='H-03'></a>H-03. The contract's funds can be drained entirely



buyLoan() is missing a check for loanToken and collateralToken

These checks are missing:
if (pool.loanToken != loan.loanToken) revert TokenMismatch();
if (pool.collateralToken != loan.collateralToken)
   revert TokenMismatch();

This allows attacker to steal all funds from the contract:
1. create (1st) pool with loanToken WETH and collateral token DMT (Dummy Malicious Token)
2. borrow WETH for DMT and get WETH back
3. startAuction
4. create another (2nd) pool with loanToken DMT
5. buyLoan from himself using the second pool
6. Since 1st pool outStandingLoan is now 0 an attacker can withdraw WETH again. Therefore they doubled their original amount

Mitigations steps:

Add these checks

if (pool.loanToken != loan.loanToken) revert TokenMismatch();
if (pool.collateralToken != loan.collateralToken)
   revert TokenMismatch();

## <a id='H-04'></a>H-04. Attacker can drain all balance of ERC777 tokens



setPool is vulnerable to the reentrancy attack which allows pool manager to drain entire ERC777 token balance of the contract.

POC:

Attacker sets a pool with pool balance of 2 TKN. Then they update it to 1 TKN. The contract will transfer them 1 TKN.

https://github.com/Cyfrin/2023-07-beedle/blob/main/src/Lender.sol#L159

Since ERC777 has callbacks it will allow the attacker to reenter the function and drain all everything from the contract.

Mitigation:

Disallow ERC777 tokens

Implement reentrancy protection

## <a id='H-05'></a>H-05. Staker contract can be drained entirely via claim



Claim() doesn't burn TKN shares
https://github.com/Cyfrin/2023-07-beedle/blob/main/src/Staking.sol#L56
so an attacker can drain all WETH from the contract

POC:

https://gist.github.com/justefg/deb2c1102fd6668405c1ba879567d215

Mitigation Steps:

Burn TKNs
## <a id='H-06'></a>H-06. Missing approve will result in a failed swap



https://github.com/Cyfrin/2023-07-beedle/blob/main/src/Fees.sol#L28

Missing approve will result in failed swap.


Mitigations steps:

Use safeApprove to zero first to support tokens implementing ERC20 race condition protection, i.e USDT.

IERC20(_profits).safeApprove(address(UNISWAP_ROUTER), 0);

IERC20(_profits).safeApprove(address(UNISWAP_ROUTER),amount);

# Medium Risk Findings

## <a id='M-01'></a>M-01. Attacker can DoS manager from removing funds from the pool



Attacker can frontrun manager's withdrawals from the pool using

https://github.com/Cyfrin/2023-07-beedle/blob/main/src/Lender.sol#L198

by running borrow()

It'll update poolBalance making withdraw requests impossible.

Migitation steps:

Implement different status for a pool: ACTIVE or PAUSED. Borrows and loan assigment should only be possible when the pool is ACIVE.
## <a id='M-02'></a>M-02. Pool manager can hike interest rates without user knowing



A pool manager can frontrun borrow with updateInterestRate by setting a really high interest rate. Then they can switch it back to normal. That way a user won't have a clue about astronomical interest rates until they have to pay the loan.

Mitigation steps:

Add aggreedInterestRate inside borrow and compare it with the one in the pool


## <a id='M-03'></a>M-03. Make MAX_AUCTION_LENGTH modifiable to adjust for changing market conditions



MAX_AUCTION_LENGTH = 3 days

should be modifiable. 3 days might be too long for some cases. UST depeg happened in less than that.

There should be a way to adjust auction length so lenders aren't at risk of getting a worthless bag.

Mitigation steps:

Allow admins to change max auction length time
## <a id='M-04'></a>M-04. Attacker can stop staking contract from paying rewards



Attacker can deposit and claim. Deposit will update the balance
and claim will decrease the contract's WETH balance.

With a large enough deposit an attacker can manipulate the balance
so this condition is always false

https://github.com/Cyfrin/2023-07-beedle/blob/main/src/Staking.sol#L65


For subsequent deposits index won't be calculated which means delta will always be zero

https://github.com/Cyfrin/2023-07-beedle/blob/main/src/Staking.sol#L86


Mitigation steps:

Updating balance when claiming
## <a id='M-05'></a>M-05. UniswapV3 incorrect swap parameters will result in a swap failure and swap at a bad rate



Hardcoded fee of 3000 (0.3 %)
https://github.com/Cyfrin/2023-07-beedle/blob/main/src/Fees.sol#L34
will cause a swap failure for tokens which don't have 0.3 % fee pools.
Another issue is swap at a bad rate because 0.3 % fee pool might have poor liquidity.

POC

https://gist.github.com/justefg/16c9d6125c45bb320fa152273015bccd

testUOSSwapCorrectFee and testUOSSwapInCorrectFee prove that not all coins have 0.3 % fee pools. In the test I used UOS which is ranked 328th on coinmarketcap. I'm sure there a lot more examples.

testUniswapFees shows that some pools have poor liquidity. In this example it's 0.01 % USDC / WETH and swapping tokens there would result in only 0.61 ETH received compared to 0.3 % and 0.05% with 0.998 and 0.999 ETH respectively.

Mitigation steps:

Add fee as a parameter along with minAmountOut

Add access control so only trusted parties could trigger it

Use an aggregator like one inch to find optimal routes or use a tool from uniswap

https://github.com/Uniswap/smart-order-router




# Gas Optimizations / Informationals

## <a id='G/I-01'></a>G/I-01. Missing length equality check for loanIds and poolIds



Add check for length equality of loanIds and poolIds

https://github.com/Cyfrin/2023-07-beedle/blob/main/src/Lender.sol#L359

