# packages/storage-0g

This package owns receipt persistence for BreakGlass.

Responsibilities:

- write local receipt mirrors
- write the latest pipeline report
- normalize receipt storage pointers
- optionally upload receipts to 0G storage

The base reliable path is local file persistence in `artifacts/receipts`.

The 0G adapter is implemented here, but live testnet uploads should still be treated as optional until the current revert issue is resolved.
