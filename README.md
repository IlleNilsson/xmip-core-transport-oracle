# xmip-core-transport-oracle

Oracle transport: one row of a query is one Stream, a send is one INSERT; TNS and TTC against a listener, as mssql and mysql are built. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
