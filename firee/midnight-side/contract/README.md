# commit.compact - deploy notes

## What this is
One circuit, `commit(hash)`, that stores the latest audit hash-chain
root hash as public on-chain state. That's the entire on-chain surface
area for the demo - no policy logic lives on-chain.

## Prereqs
- Compact CLI (`compactc`) installed
- Lace Midnight Preview wallet, funded with tDUST from the testnet faucet
- Local proof server running

## Compile
```
compactc contract/commit.compact -o build/commit.json
```

## Deploy (fill in once you've run it)
- Network: testnet
- Wallet used:
- Contract address:
- Deploy tx hash:
- Date/time deployed:

## Fallback
If deploy isn't working close to demo time, see
`../docs/fallback_demo.md` - show this file + the compiled contract
alongside a fully-working local hash chain + verify.py demo instead of
a live testnet call.
