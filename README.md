# xmip-core-transport-oracle

Oracle transport: one row of a query is one Stream, a send is one INSERT; TNS and TTC against a listener, as mssql and mysql are built. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A send binds the Stream as one RAW: `INSERT INTO "<table>" ("<column>") VALUES (:1)`.
Where a send target puts its row — `oracle://host:port/<service>/<table>/<column>`,
`host:port/<service>/<table>/<column>` or `<table>/<column>` — and the INSERT,
its table and column always quoted identifiers so a target can name nothing
but them, are `xmip-core-transport`'s `sql` module; this crate hands it its
`DIALECT`: the scheme `oracle`, a service, double quotes. A quoted identifier
keeps its case, so a target names a table as the dictionary stores it:
`INBOX/PAYLOAD` for one created unquoted.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
