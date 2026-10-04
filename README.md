# xmip-core-transport-oracle

Oracle transport: one row of a query is one Stream, a send is one INSERT; TNS and TTC against a listener, as mssql and mysql are built. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

## Acknowledgement

The Location's query only reads; what consumes a row is the `accept` statement, run after the row's receive cycle. `accept` (text, receive side, optional) is a statement — `DELETE FROM inbox WHERE id = :1`, an `UPDATE` of a status column — with the row's name, the query's first column as the origin carries it, in place of `:1` (Oracle's first positional bind, the one the INSERT carries its RAW in; the `accept` statement carries its name as a literal instead, since a name bound as RAW would not compare to a number or text column), written as a string literal by the dialect's string quoting (`'…'`, a quote doubled) (`transport::sql::accept`), so whatever the column holds stays one value. It runs on the session kept for the server and service, and committed (`COMMIT`), since a kept session is not logged off:

- **Accepted**: `accept` runs; the row is consumed once its Stream is Xmip's.
- **Refused**: nothing runs. A refusal is not a consumption: the row is the only copy, so it is left where it lies, and this Location does not receive it again while its body is unchanged; a row whose body changed is a new arrival. The memory is the node process's (`transport::refused`).
- **Failed**: nothing runs, and the next receive reads the row again.

A row whose first column is NULL has no name to bind, and nothing runs for it. Where `accept` is left out a row's verdict tells the database nothing: every row is read again unless the query keeps it from that, and a query that consumes as it reads — a `DELETE … RETURNING`, an `UPDATE` of a status column — consumes before the receive cycle has run: acceptance is then at-most-once. Each row is a whole value of the result, read whole.

A send binds the Stream as one RAW: `INSERT INTO "<table>" ("<column>") VALUES (:1)`.
Where a send target puts its row — `oracle://host:port/<service>/<table>/<column>`,
`host:port/<service>/<table>/<column>` or `<table>/<column>` — and the INSERT,
its table and column always quoted identifiers so a target can name nothing
but them, are `xmip-core-transport`'s `sql` module; this crate hands it its
`DIALECT`: the scheme `oracle`, a service, double quotes. A quoted identifier
keeps its case, so a target names a table as the dictionary stores it:
`INBOX/PAYLOAD` for one created unquoted.

A Send Location inserts on a session logged in once per server and service and kept (`transport::Pool`), and commits each insert, since the logoff that committed it no longer follows. The login is the transport capability's `Login`. Until 2026-09-27 every insert connected, negotiated and logged in.

A Receive Location runs its query on a session kept the same way: logged in on its first receive and reused by every receive after, replaced where the listener closed it. Until 2026-09-28 every receive logged in and off.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
