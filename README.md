# xmip-core-transport-oracle

Oracle Database transport: one row of a query is one Stream, a send is one
INSERT. A technology of
[xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).
Oracle is a transport here and nothing more: no Storage server speaks it, and
nothing of it is in the foundation (the owner, 2026-10-14).

The transport is every SQL technology's, `transport::sql::SqlTransport`, over
this crate's `Oracle` wire (2026-11-13): its name and scheme, its settings —
`service` in place of a database — the Oracle dialect, the commit after every
statement, and the wire below, both halves, which stays here (`accept_one`
serves the far end).

## What it speaks

A session goes as Oracle Net goes: a TNS connect naming the service and its
accept (`tns.rs`), then, inside data packets, the two-task layer's order
(`ttc.rs`) — a protocol exchange, a data-type exchange, a challenge and its
answer, a statement executed and its rows fetched, a logoff. A message over
one packet is cut into as many as it takes and joined whole, up to
`net::MAX_BODY`.

**The bodies are not yet Oracle's.** There are no TTC function codes, no
capability negotiation and no O5LOGON: Oracle Database 11g and later log in
with a session key exchanged under AES and a password verifier — the 11g
verifier over SHA-1, the 12c verifier over PBKDF2 with SHA-512 — and neither is
written here. The answer to the challenge is a keyed mix that only this crate's
own far end (`session.rs`) checks. A real Oracle listener refuses this client,
and an Oracle client refuses this far end. TCPS is not spoken; where it is, it
is `xmip-core-library-tls`'s (ADR-0033).

## Rows and the payload column

The SQL it writes and its far end reads — `"…"` identifiers, `'…'` literals
with the quote doubled, `HEXTORAW('…')`, the one INSERT with its table and
column always quoted identifiers so a target can name nothing but them, and a
statement's verb — is Oracle's as `xmip-core-library-sql` writes it
(`sql::ORACLE`), the one SQL in the estate. A quoted identifier keeps its case,
so a target names a table as the dictionary stores it: `INBOX/PAYLOAD` for one
created unquoted.

Where a send target puts its row —
`oracle://host:port/<service>/<table>/<column>`,
`host:port/<service>/<table>/<column>` or `<table>/<column>` — is
`xmip-core-transport`'s `sql` module; this crate hands it its scheme, `oracle`.

The payload column holds bytes unless the Location declares otherwise
(ADR-0038: a payload is bytes). `column = "binary"`, the default, writes every
Stream as `HEXTORAW('…')` and reads a value back only as bare hex, so a binary
column's receive query spells it out: `SELECT id, RAWTOHEX(payload) FROM inbox`.
`column = "text"` decodes the Stream strictly in its `encoding` — `utf-8`
unless `utf-16le`, `utf-16be`, `utf-32le` or `utf-32be` is named — writes it as
a string literal, and encodes a value read back to that form. A Stream or a
value that is not its declared form is refused, never repaired; so is a row
value that is not UTF-8. The two settings and the rule are
`xmip-core-transport`'s `sql` module, shared by every SQL transport.

A Location's receive runs its query and returns at once (`Waiting::Polled`):
after a receive that found nothing, the runtime waits its poll interval.

## Acknowledgement

`accept` is every SQL technology's (`transport::sql::accept`):
[xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport)'s
README. On Oracle it is a statement — `DELETE FROM inbox WHERE id = :1`, an
`UPDATE` of a status column — with the row's name in place of `:1`, written as
Oracle's string literal; it runs on the session kept for the server and
service, and is committed.

A Send Location inserts on a session logged in once per server and service and
kept (`transport::Pool`), and commits each insert. A Receive Location runs its
query on a session kept the same way, replaced where the listener closed it.
The login is the transport capability's `Login`; the password is the secret the
Location names, never a setting.

## The declaration

What a Location of this technology is configured with is two `const`s in its
`declaration` module, `src/declaration.rs`, beside the code, which its wire hands
`transport::sql`'s `Configured` (ADR-0064, amendment 2026-11-26):
`declaration::SETTINGS`, `service`, `user`, `query`, `accept`, `column`,
`encoding` and `timeout`, each but `service` what every SQL Location declares
(`transport::sql`), and `SCHEMES`, `oracle`; `service` is `declaration::SERVICE`,
which the wire names its database by. Built with its `declaration` feature alone
(`--no-default-features --features declaration`), the crate is those and nothing
more: its code and every crate the code is built on are behind the default
feature. So the library the surfaces load carries it without the code, through
the gathering crate xmip-core-declaration (open problem 48), and the language
server and the desktop suggest and check an Oracle Location's settings though no
node in their process loaded the technology. `test/Declaration.Test.ps1` in the
estate holds that the declaration builds nothing the transport capability does
not.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
